use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};

use chrono::{DateTime, Duration as ChronoDuration, Months, TimeZone, Utc};
use cron::Schedule;
use nezha_core::{CRON_COVER_ALERT_TRIGGER, TaskType};
use serde_json::Value;
use tracing::{debug, warn};

use crate::{
    DashboardState, is_service_monitor_task, notification,
    store::{
        AlertRuleResource, CronResource, CycleTransferStats, PublicServer, ServiceResource, Store,
    },
    unix_now,
};

const CRON_TYPE_CRON_TASK: u8 = 0;
const CRON_COVER_IGNORE_ALL: u8 = 0;
const CRON_COVER_ALL: u8 = 1;
const ALERT_MODE_ALWAYS_TRIGGER: u8 = 0;
const RULE_CHECK_FAIL: u8 = 1;
const RULE_CHECK_PASS: u8 = 2;

#[derive(Debug, Default)]
pub(crate) struct AlertRuntime {
    samples: HashMap<u64, HashMap<u64, Vec<Vec<bool>>>>,
    prev_state: HashMap<u64, HashMap<u64, u8>>,
    next_transfer_checks: HashMap<(u64, u64, usize), u64>,
    last_transfer_status: HashMap<(u64, u64, usize), bool>,
    cycle_transfer_stats: HashMap<u64, CycleTransferStats>,
}

pub(crate) async fn cron_scheduler(state: Arc<DashboardState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if let Err(err) = tick_crons(&state).await {
            warn!(%err, "cron scheduler tick failed");
        }
    }
}

pub(crate) async fn service_monitor_scheduler(state: Arc<DashboardState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_dispatched = HashMap::new();
    loop {
        interval.tick().await;
        if let Err(err) = tick_service_monitors(&state, &mut last_dispatched).await {
            warn!(%err, "service monitor scheduler tick failed");
        }
    }
}

pub(crate) async fn alert_scheduler(state: Arc<DashboardState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(3));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut runtime = AlertRuntime::default();
    loop {
        interval.tick().await;
        if let Err(err) = tick_alerts(&state, &mut runtime).await {
            warn!(%err, "alert scheduler tick failed");
        }
    }
}

pub(crate) async fn tick_crons(state: &DashboardState) -> anyhow::Result<()> {
    let now = Utc::now();
    let due = {
        let store = state
            .store
            .lock()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
        store
            .list_crons()?
            .into_iter()
            .filter(|cron| {
                cron.task_type == CRON_TYPE_CRON_TASK && cron_due(cron, now.timestamp() as u64)
            })
            .collect::<Vec<_>>()
    };

    for cron in due {
        let dispatched = dispatch_cron(state, &cron).await;
        if let Ok(store) = state.store.lock() {
            let _ = store.record_cron_execution(cron.id, dispatched > 0);
        }
        debug!(cron_id = cron.id, dispatched, "cron task dispatched");
    }
    Ok(())
}

pub(crate) async fn dispatch_cron(state: &DashboardState, cron: &CronResource) -> usize {
    let (success, _) = dispatch_cron_detailed(state, cron).await;
    success.len()
}

pub(crate) async fn dispatch_cron_detailed(
    state: &DashboardState,
    cron: &CronResource,
) -> (Vec<u64>, Vec<u64>) {
    let servers = {
        let Ok(store) = state.store.lock() else {
            return (Vec::new(), Vec::new());
        };
        let Ok(servers) = store.list_servers() else {
            return (Vec::new(), Vec::new());
        };
        servers
    };
    let selected = servers
        .into_iter()
        .filter(|server| cron_can_send_to_server(cron, server.user_id))
        .filter(|server| cron_covers_server(cron, server.id))
        .map(|server| server.id)
        .collect::<Vec<_>>();

    let mut success = Vec::new();
    let mut offline = Vec::new();
    for server_id in selected {
        if state
            .dispatch_task_with_id(server_id, cron.id, TaskType::Command, cron.command.clone())
            .await
        {
            success.push(server_id);
        } else {
            offline.push(server_id);
        }
    }
    (success, offline)
}

pub(crate) async fn tick_service_monitors(
    state: &DashboardState,
    last_dispatched: &mut HashMap<u64, u64>,
) -> anyhow::Result<()> {
    let now = unix_now();
    let due = {
        let store = state
            .store
            .lock()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
        store
            .list_services()?
            .into_iter()
            .filter(|service| is_service_monitor_task(service.r#type as u64))
            .filter(|service| service_due(service, now, last_dispatched))
            .map(|service| {
                let targets = store.service_targets(&service)?;
                Ok((service, targets))
            })
            .collect::<anyhow::Result<Vec<_>>>()?
    };

    for (service, targets) in due {
        let Some(task_type) = TaskType::from_u64(service.r#type as u64) else {
            continue;
        };
        let mut dispatched = 0;
        for server_id in targets {
            if state
                .dispatch_task_with_id(server_id, service.id, task_type, service.target.clone())
                .await
            {
                dispatched += 1;
            }
        }
        last_dispatched.insert(service.id, now);
        debug!(
            service_id = service.id,
            dispatched, "service monitor task dispatched"
        );
    }
    Ok(())
}

pub(crate) async fn tick_alerts(
    state: &DashboardState,
    runtime: &mut AlertRuntime,
) -> anyhow::Result<()> {
    let (actions, cycle_transfer_stats) = {
        let store = state
            .store
            .lock()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
        let alerts = store
            .list_alert_rules()?
            .into_iter()
            .filter(alert_enabled)
            .collect::<Vec<_>>();
        let servers = store.list_servers()?;
        let crons = store.list_crons()?;
        let now = unix_now();
        let mut actions = Vec::new();
        let mut cycle_transfer_stats = HashMap::new();

        for alert in alerts {
            let alert_owner_is_admin = store.user_is_admin(alert.user_id)?;
            ensure_alert_cycle_transfer_stats(&alert, &mut cycle_transfer_stats, now);
            for server in &servers {
                if alert.user_id != server.user_id && !alert_owner_is_admin {
                    continue;
                }
                let point = alert_snapshot(
                    &alert,
                    server,
                    &store,
                    now,
                    runtime,
                    cycle_transfer_stats.get_mut(&alert.id),
                );
                let server_samples = runtime
                    .samples
                    .entry(alert.id)
                    .or_default()
                    .entry(server.id)
                    .or_default();
                server_samples.push(point);
                let (max_samples, passed) = alert_check(&alert, server_samples);
                let alert_prev = runtime
                    .prev_state
                    .entry(alert.id)
                    .or_default()
                    .entry(server.id)
                    .or_default();

                if !passed {
                    if alert.trigger_mode == ALERT_MODE_ALWAYS_TRIGGER
                        || *alert_prev != RULE_CHECK_FAIL
                    {
                        *alert_prev = RULE_CHECK_FAIL;
                        actions.push(AlertAction::incident(
                            &alert,
                            server,
                            &crons,
                            alert_owner_is_admin,
                        ));
                    }
                } else {
                    if *alert_prev == RULE_CHECK_FAIL {
                        actions.push(AlertAction::resolved(
                            &alert,
                            server,
                            &crons,
                            alert_owner_is_admin,
                        ));
                    }
                    *alert_prev = RULE_CHECK_PASS;
                }

                if max_samples > 0 && max_samples < server_samples.len() {
                    let keep_from = server_samples.len() - max_samples;
                    server_samples.drain(..keep_from);
                }
            }
        }
        (actions, cycle_transfer_stats)
    };

    runtime.cycle_transfer_stats = cycle_transfer_stats.clone();
    *state.cycle_transfer_stats.write().await = cycle_transfer_stats;

    for action in actions {
        for cron in action.trigger_crons {
            if state
                .dispatch_task_with_id(
                    action.server_id,
                    cron.id,
                    TaskType::Command,
                    cron.command.clone(),
                )
                .await
            {
                state.reserve_alert_trigger_result(cron.id, action.server_id);
            } else {
                state.revoke_alert_trigger_result(cron.id, action.server_id);
            }
        }

        let notifications = {
            let store = state
                .store
                .lock()
                .map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
            store.notifications_for_group(action.notification_group_id)?
        };
        for (id, result) in
            notification::send_notification_group(notifications, &action.message).await
        {
            if let Err(err) = result {
                warn!(notification_id = id, %err, "failed to send alert notification");
            }
        }
    }

    Ok(())
}

fn cron_due(cron: &CronResource, now_unix: u64) -> bool {
    let Some(last) = cron.last_executed_at else {
        return next_after(&cron.scheduler, now_unix.saturating_sub(1))
            .is_some_and(|next| next <= now_unix);
    };
    next_after(&cron.scheduler, last).is_some_and(|next| next <= now_unix)
}

fn service_due(
    service: &ServiceResource,
    now_unix: u64,
    last_dispatched: &HashMap<u64, u64>,
) -> bool {
    let interval = service.duration.max(30);
    last_dispatched
        .get(&service.id)
        .is_none_or(|last| last.saturating_add(interval) <= now_unix)
}

fn next_after(scheduler: &str, after_unix: u64) -> Option<u64> {
    let schedule = Schedule::from_str(scheduler).ok()?;
    let after = Utc.timestamp_opt(after_unix as i64, 0).single()?;
    schedule
        .after(&after)
        .next()
        .map(|time| time.timestamp() as u64)
}

fn cron_can_send_to_server(cron: &CronResource, server_user_id: u64) -> bool {
    cron.user_id == 0 || cron.user_id == server_user_id
}

fn cron_covers_server(cron: &CronResource, server_id: u64) -> bool {
    match cron.cover {
        CRON_COVER_ALL => !cron.servers.contains(&server_id),
        CRON_COVER_IGNORE_ALL => cron.servers.contains(&server_id),
        _ => false,
    }
}

#[derive(Debug)]
struct AlertAction {
    server_id: u64,
    notification_group_id: u64,
    message: String,
    trigger_crons: Vec<CronResource>,
}

impl AlertAction {
    fn incident(
        alert: &AlertRuleResource,
        server: &PublicServer,
        crons: &[CronResource],
        alert_owner_is_admin: bool,
    ) -> Self {
        Self::new(
            "Incident",
            alert,
            server,
            crons,
            &alert.fail_trigger_tasks,
            alert_owner_is_admin,
        )
    }

    fn resolved(
        alert: &AlertRuleResource,
        server: &PublicServer,
        crons: &[CronResource],
        alert_owner_is_admin: bool,
    ) -> Self {
        Self::new(
            "Resolved",
            alert,
            server,
            crons,
            &alert.recover_trigger_tasks,
            alert_owner_is_admin,
        )
    }

    fn new(
        status: &str,
        alert: &AlertRuleResource,
        server: &PublicServer,
        crons: &[CronResource],
        trigger_task_ids: &[u64],
        alert_owner_is_admin: bool,
    ) -> Self {
        let trigger_crons = crons
            .iter()
            .filter(|cron| trigger_task_ids.contains(&cron.id))
            .filter(|cron| cron.cover == CRON_COVER_ALERT_TRIGGER)
            .filter(|cron| alert_owner_is_admin || cron.user_id == alert.user_id)
            .cloned()
            .collect();
        Self {
            server_id: server.id,
            notification_group_id: alert.notification_group_id,
            message: format!("[{status}] {} {}", server.name, alert.name),
            trigger_crons,
        }
    }
}

fn alert_enabled(alert: &AlertRuleResource) -> bool {
    alert.enable.unwrap_or(false) && !alert.rules.is_empty()
}

fn alert_snapshot(
    alert: &AlertRuleResource,
    server: &PublicServer,
    store: &Store,
    now_unix: u64,
    runtime: &mut AlertRuntime,
    cycle_transfer_stats: Option<&mut CycleTransferStats>,
) -> Vec<bool> {
    let mut point = Vec::with_capacity(alert.rules.len());
    let mut cycle_transfer_stats = cycle_transfer_stats;
    for (rule_index, rule) in alert.rules.iter().enumerate() {
        point.push(rule_snapshot(
            alert.id,
            rule_index,
            rule,
            server,
            store,
            now_unix,
            runtime,
            cycle_transfer_stats.as_deref_mut(),
        ));
    }
    point
}

fn alert_check(alert: &AlertRuleResource, points: &[Vec<bool>]) -> (usize, bool) {
    let mut has_passed_rule = false;
    let mut durations = vec![1_usize; alert.rules.len()];

    for (rule_index, rule) in alert.rules.iter().enumerate() {
        let duration = rule_duration(rule).max(1);
        let rule_type = rule.get("type").and_then(Value::as_str).unwrap_or_default();

        if is_transfer_cycle_rule(rule_type) {
            durations[rule_index] = 1;
            if has_passed_rule {
                continue;
            }
            if points
                .last()
                .and_then(|point| point.get(rule_index))
                .copied()
                .unwrap_or(true)
            {
                has_passed_rule = true;
            }
        } else if is_offline_rule(rule_type) {
            if has_passed_rule || points.len() < duration {
                has_passed_rule = true;
                continue;
            }
            let mut fail = 0_usize;
            for point in points[points.len() - duration..].iter().rev() {
                fail += 1;
                if point.get(rule_index).copied().unwrap_or(true) {
                    has_passed_rule = true;
                    break;
                }
            }
            durations[rule_index] = fail;
        } else {
            durations[rule_index] = duration;
            if has_passed_rule || points.len() < duration {
                has_passed_rule = true;
                continue;
            }
            let mut fail = 0_usize;
            for point in &points[points.len() - duration..] {
                if !point.get(rule_index).copied().unwrap_or(true) {
                    fail += 1;
                }
            }
            if fail * 100 / duration <= 70 {
                has_passed_rule = true;
            }
        }
    }

    (durations.into_iter().max().unwrap_or(1), has_passed_rule)
}

fn rule_snapshot(
    alert_id: u64,
    rule_index: usize,
    rule: &Value,
    server: &PublicServer,
    store: &Store,
    now_unix: u64,
    runtime: &mut AlertRuntime,
    cycle_transfer_stats: Option<&mut CycleTransferStats>,
) -> bool {
    if rule_excludes_server(rule, server.id) {
        return true;
    }

    let rule_type = rule.get("type").and_then(Value::as_str).unwrap_or_default();
    if is_offline_rule(rule_type) {
        return server.last_active != 0 && now_unix.saturating_sub(server.last_active) <= 6;
    }

    if is_transfer_cycle_rule(rule_type) {
        let key = (alert_id, server.id, rule_index);
        if runtime
            .next_transfer_checks
            .get(&key)
            .is_some_and(|next| *next > now_unix)
        {
            if let Some(stats) = cycle_transfer_stats {
                copy_cached_cycle_transfer_stats(
                    runtime.cycle_transfer_stats.get(&alert_id),
                    stats,
                    server.id,
                );
            }
            return runtime
                .last_transfer_status
                .get(&key)
                .copied()
                .unwrap_or(true);
        }
    }

    let Some(src) = rule_value(rule_type, rule, server, store, now_unix) else {
        return true;
    };
    let min = rule.get("min").and_then(Value::as_f64).unwrap_or_default();
    let max = rule.get("max").and_then(Value::as_f64).unwrap_or_default();
    let passed = !((max > 0.0 && src > max) || (min > 0.0 && src < min));

    if is_transfer_cycle_rule(rule_type) {
        let key = (alert_id, server.id, rule_index);
        let next_update = cycle_rule_next_update(max, src, now_unix);
        runtime.next_transfer_checks.insert(key, next_update);
        runtime.last_transfer_status.insert(key, passed);
        if let Some(stats) = cycle_transfer_stats {
            update_cycle_transfer_stats(rule, stats, server, src, next_update, now_unix);
        }
    }

    passed
}

fn rule_excludes_server(rule: &Value, server_id: u64) -> bool {
    let cover = rule
        .get("cover")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let ignored = rule
        .get("ignore")
        .and_then(Value::as_object)
        .and_then(|items| items.get(&server_id.to_string()))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match cover {
        0 => ignored,
        1 => !ignored,
        _ => false,
    }
}

fn rule_value(
    rule_type: &str,
    rule: &Value,
    server: &PublicServer,
    store: &Store,
    _now_unix: u64,
) -> Option<f64> {
    let state = server.state.as_ref();
    let host = server.host.as_ref();
    Some(match rule_type {
        "cpu" => state?.cpu,
        "gpu_max" => state?.gpu.iter().copied().fold(0.0_f64, f64::max),
        "memory" => percentage(state?.mem_used, host?.mem_total),
        "swap" => percentage(state?.swap_used, host?.swap_total),
        "disk" => percentage(state?.disk_used, host?.disk_total),
        "net_in_speed" => state?.net_in_speed as f64,
        "net_out_speed" => state?.net_out_speed as f64,
        "net_all_speed" => state?.net_out_speed.saturating_add(state?.net_out_speed) as f64,
        "transfer_in" => state?.net_in_transfer as f64,
        "transfer_out" => state?.net_out_transfer as f64,
        "transfer_all" => state?
            .net_out_transfer
            .saturating_add(state?.net_in_transfer) as f64,
        "transfer_in_cycle" => transfer_cycle_value(rule, server, store, TransferCycleKind::In)?,
        "transfer_out_cycle" => transfer_cycle_value(rule, server, store, TransferCycleKind::Out)?,
        "transfer_all_cycle" => transfer_cycle_value(rule, server, store, TransferCycleKind::All)?,
        "load1" => state?.load1,
        "load5" => state?.load5,
        "load15" => state?.load15,
        "tcp_conn_count" => state?.tcp_conn_count as f64,
        "udp_conn_count" => state?.udp_conn_count as f64,
        "process_count" => state?.process_count as f64,
        "temperature_max" => state?
            .temperatures
            .iter()
            .map(|item| item.temperature)
            .fold(0.0_f64, f64::max),
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy)]
enum TransferCycleKind {
    In,
    Out,
    All,
}

fn transfer_cycle_value(
    rule: &Value,
    server: &PublicServer,
    store: &Store,
    kind: TransferCycleKind,
) -> Option<f64> {
    let state = server.state.as_ref()?;
    let current_in = state
        .net_in_transfer
        .saturating_sub(server.prev_transfer_in_snapshot);
    let current_out = state
        .net_out_transfer
        .saturating_sub(server.prev_transfer_out_snapshot);
    let interval = rule
        .get("cycle_interval")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let (stored_in, stored_out) = if interval == 0 {
        (0, 0)
    } else {
        let since = transfer_cycle_start(rule, unix_now())?;
        store.transfer_totals_since(server.id, since).ok()?
    };
    Some(match kind {
        TransferCycleKind::In => stored_in.saturating_add(current_in),
        TransferCycleKind::Out => stored_out.saturating_add(current_out),
        TransferCycleKind::All => stored_in
            .saturating_add(stored_out)
            .saturating_add(current_in)
            .saturating_add(current_out),
    } as f64)
}

fn transfer_cycle_start(rule: &Value, now_unix: u64) -> Option<u64> {
    let start = rule.get("cycle_start").and_then(parse_cycle_start)?;
    let interval = rule.get("cycle_interval").and_then(Value::as_u64)?;
    if interval == 0 {
        return Some(start.timestamp().max(0) as u64);
    }
    let unit = rule
        .get("cycle_unit")
        .and_then(Value::as_str)
        .unwrap_or("hour")
        .to_ascii_lowercase();
    let now = Utc.timestamp_opt(now_unix as i64, 0).single()?;
    let mut current = start;
    let mut next = add_cycle_interval(current, &unit, interval)?;
    while now > next {
        current = next;
        next = add_cycle_interval(current, &unit, interval)?;
    }
    Some(current.timestamp().max(0) as u64)
}

fn transfer_cycle_end(rule: &Value, now_unix: u64) -> Option<u64> {
    let start = transfer_cycle_start(rule, now_unix)?;
    let unit = rule
        .get("cycle_unit")
        .and_then(Value::as_str)
        .unwrap_or("hour")
        .to_ascii_lowercase();
    let start = Utc.timestamp_opt(start as i64, 0).single()?;
    add_cycle_interval(
        start,
        &unit,
        rule.get("cycle_interval")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    )
    .map(|time| time.timestamp().max(0) as u64)
}

fn parse_cycle_start(value: &Value) -> Option<DateTime<Utc>> {
    if let Some(raw) = value.as_str() {
        return DateTime::parse_from_rfc3339(raw)
            .ok()
            .map(|time| time.with_timezone(&Utc));
    }
    if let Some(unix) = value.as_i64() {
        return Utc.timestamp_opt(unix, 0).single();
    }
    value
        .as_u64()
        .and_then(|unix| Utc.timestamp_opt(unix as i64, 0).single())
}

fn add_cycle_interval(time: DateTime<Utc>, unit: &str, interval: u64) -> Option<DateTime<Utc>> {
    match unit {
        "year" => time.checked_add_months(Months::new((interval * 12).try_into().ok()?)),
        "month" => time.checked_add_months(Months::new(interval.try_into().ok()?)),
        "week" => time.checked_add_signed(ChronoDuration::weeks(interval.try_into().ok()?)),
        "day" => time.checked_add_signed(ChronoDuration::days(interval.try_into().ok()?)),
        _ => time.checked_add_signed(ChronoDuration::seconds(
            interval.checked_mul(3600)?.try_into().ok()?,
        )),
    }
}

fn is_transfer_cycle_rule(rule_type: &str) -> bool {
    rule_type.ends_with("_cycle")
}

fn is_offline_rule(rule_type: &str) -> bool {
    rule_type == "offline"
}

fn percentage(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        used as f64 * 100.0 / total as f64
    }
}

fn rule_duration(rule: &Value) -> usize {
    rule.get("duration")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        .max(1) as usize
}

fn ensure_alert_cycle_transfer_stats(
    alert: &AlertRuleResource,
    cycle_transfer_stats: &mut HashMap<u64, CycleTransferStats>,
    now_unix: u64,
) {
    let Some(rule) = alert
        .rules
        .iter()
        .find(|rule| is_transfer_cycle_rule(rule_type(rule).unwrap_or_default()))
    else {
        return;
    };
    let Some(from) = transfer_cycle_start(rule, now_unix)
        .and_then(|unix| Utc.timestamp_opt(unix as i64, 0).single())
    else {
        return;
    };
    let Some(to) = transfer_cycle_end(rule, now_unix)
        .and_then(|unix| Utc.timestamp_opt(unix as i64, 0).single())
    else {
        return;
    };
    cycle_transfer_stats
        .entry(alert.id)
        .or_insert_with(|| CycleTransferStats {
            name: alert.name.clone(),
            from,
            to,
            max: rule.get("max").and_then(Value::as_u64).unwrap_or_default(),
            min: rule.get("min").and_then(Value::as_u64).unwrap_or_default(),
            server_name: HashMap::new(),
            transfer: HashMap::new(),
            next_update: HashMap::new(),
        });
}

fn copy_cached_cycle_transfer_stats(
    cached: Option<&CycleTransferStats>,
    current: &mut CycleTransferStats,
    server_id: u64,
) {
    let Some(cached) = cached else {
        return;
    };
    current.from = cached.from;
    current.to = cached.to;
    if let Some(name) = cached.server_name.get(&server_id) {
        current.server_name.insert(server_id, name.clone());
    }
    if let Some(transfer) = cached.transfer.get(&server_id) {
        current.transfer.insert(server_id, *transfer);
    }
    if let Some(next_update) = cached.next_update.get(&server_id) {
        current.next_update.insert(server_id, *next_update);
    }
}

fn update_cycle_transfer_stats(
    rule: &Value,
    stats: &mut CycleTransferStats,
    server: &PublicServer,
    src: f64,
    next_update_unix: u64,
    now_unix: u64,
) {
    if let Some(from) = transfer_cycle_start(rule, now_unix)
        .and_then(|unix| Utc.timestamp_opt(unix as i64, 0).single())
    {
        stats.from = from;
    }
    if let Some(to) = transfer_cycle_end(rule, now_unix)
        .and_then(|unix| Utc.timestamp_opt(unix as i64, 0).single())
    {
        stats.to = to;
    }
    stats.server_name.insert(server.id, server.name.clone());
    stats.transfer.insert(server.id, src.max(0.0) as u64);
    if let Some(next_update) = Utc.timestamp_opt(next_update_unix as i64, 0).single() {
        stats.next_update.insert(server.id, next_update);
    }
}

fn cycle_rule_next_update(max: f64, src: f64, now_unix: u64) -> u64 {
    let seconds = if max > 0.0 {
        (1800.0 * ((max - src) / max)).max(180.0)
    } else {
        180.0
    };
    now_unix.saturating_add(seconds.max(0.0).round() as u64)
}

fn rule_type(rule: &Value) -> Option<&str> {
    rule.get("type").and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn cron_fixture() -> CronResource {
        CronResource {
            id: 1,
            user_id: 42,
            name: "test".into(),
            task_type: CRON_TYPE_CRON_TASK,
            scheduler: "0/5 * * * * * *".into(),
            command: "uptime".into(),
            servers: vec![7],
            push_successful: false,
            notification_group_id: 0,
            last_executed_at: None,
            last_result: false,
            cover: CRON_COVER_IGNORE_ALL,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn detects_due_cron_from_last_execution() {
        let mut cron = cron_fixture();
        cron.last_executed_at = Some(10);
        assert!(cron_due(&cron, 15));
        assert!(!cron_due(&cron, 14));
    }

    #[test]
    fn cron_cover_matches_upstream_semantics() {
        let mut cron = cron_fixture();
        cron.cover = CRON_COVER_IGNORE_ALL;
        cron.servers = vec![1, 2];
        assert!(cron_covers_server(&cron, 1));
        assert!(!cron_covers_server(&cron, 3));

        cron.cover = CRON_COVER_ALL;
        assert!(!cron_covers_server(&cron, 1));
        assert!(cron_covers_server(&cron, 3));
    }

    #[tokio::test]
    async fn tick_dispatches_due_cron_to_selected_online_server() {
        let state = Arc::new(crate::DashboardState::new_for_test());
        let server_id = {
            let store = state.store.lock().unwrap();
            let stored = store
                .ensure_server_for_user(uuid::Uuid::new_v4(), 0)
                .unwrap();
            store.move_servers(&[stored.id], 42).unwrap();
            store
                .upsert_cron(
                    None,
                    42,
                    &serde_json::json!({
                        "name": "test",
                        "task_type": 0,
                        "scheduler": "0/1 * * * * * *",
                        "command": "echo hi",
                        "servers": [stored.id],
                        "cover": 0
                    }),
                )
                .unwrap();
            stored.id
        };
        let (tx, mut rx) = mpsc::channel(1);
        state.task_senders.write().await.insert(server_id, tx);

        tick_crons(&state).await.unwrap();

        let task = rx.recv().await.expect("cron task");
        assert_eq!(task.id, 1);
        assert_eq!(task.r#type, TaskType::Command.as_u64());
        assert_eq!(task.data, "echo hi");

        let crons = state.store.lock().unwrap().list_crons().unwrap();
        assert!(crons[0].last_executed_at.is_some());
        assert!(crons[0].last_result);
    }

    #[tokio::test]
    async fn tick_dispatches_due_service_with_service_id() {
        let state = Arc::new(crate::DashboardState::new_for_test());
        let server_id = {
            let store = state.store.lock().unwrap();
            let stored = store
                .ensure_server_for_user(uuid::Uuid::new_v4(), 0)
                .unwrap();
            store
                .upsert_service(
                    None,
                    0,
                    &serde_json::json!({
                        "name": "tcp",
                        "type": TaskType::TcpPing.as_u64(),
                        "target": "example.com:443",
                        "duration": 30,
                        "cover": 1,
                        "skip_servers": { (stored.id.to_string()): true }
                    }),
                )
                .unwrap();
            stored.id
        };
        let (tx, mut rx) = mpsc::channel(1);
        state.task_senders.write().await.insert(server_id, tx);
        let mut last_dispatched = HashMap::new();

        tick_service_monitors(&state, &mut last_dispatched)
            .await
            .unwrap();

        let task = rx.recv().await.expect("service task");
        assert_eq!(task.id, 1);
        assert_eq!(task.r#type, TaskType::TcpPing.as_u64());
        assert_eq!(task.data, "example.com:443");
        assert!(last_dispatched.contains_key(&1));
    }

    #[tokio::test]
    async fn service_tick_respects_cover_selection() {
        let state = Arc::new(crate::DashboardState::new_for_test());
        let (covered_id, skipped_id) = {
            let store = state.store.lock().unwrap();
            let covered = store
                .ensure_server_for_user(uuid::Uuid::new_v4(), 0)
                .unwrap();
            let skipped = store
                .ensure_server_for_user(uuid::Uuid::new_v4(), 0)
                .unwrap();
            store
                .upsert_service(
                    None,
                    0,
                    &serde_json::json!({
                        "name": "http",
                        "type": TaskType::HttpGet.as_u64(),
                        "target": "https://example.com",
                        "duration": 30,
                        "cover": 0,
                        "skip_servers": { (skipped.id.to_string()): true }
                    }),
                )
                .unwrap();
            (covered.id, skipped.id)
        };
        let (covered_tx, mut covered_rx) = mpsc::channel(1);
        let (skipped_tx, mut skipped_rx) = mpsc::channel(1);
        state
            .task_senders
            .write()
            .await
            .insert(covered_id, covered_tx);
        state
            .task_senders
            .write()
            .await
            .insert(skipped_id, skipped_tx);
        let mut last_dispatched = HashMap::new();

        tick_service_monitors(&state, &mut last_dispatched)
            .await
            .unwrap();

        assert!(covered_rx.try_recv().is_ok());
        assert!(skipped_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn alert_tick_dispatches_trigger_task_on_incident() {
        let state = Arc::new(crate::DashboardState::new_for_test());
        let server_id = {
            let store = state.store.lock().unwrap();
            let uuid = uuid::Uuid::new_v4();
            let stored = store.ensure_server_for_user(uuid, 0).unwrap();
            store
                .update_host_for_user(
                    uuid,
                    0,
                    nezha_proto::Host {
                        mem_total: 100,
                        disk_total: 100,
                        ..Default::default()
                    },
                )
                .unwrap();
            store
                .update_state_for_user(
                    uuid,
                    0,
                    nezha_proto::State {
                        cpu: 99.0,
                        mem_used: 80,
                        disk_used: 80,
                        ..Default::default()
                    },
                )
                .unwrap();
            let cron = store
                .upsert_cron(
                    None,
                    0,
                    &serde_json::json!({
                        "name": "trigger",
                        "task_type": 1,
                        "command": "echo alert",
                        "cover": CRON_COVER_ALERT_TRIGGER
                    }),
                )
                .unwrap();
            store
                .upsert_alert_rule(
                    None,
                    0,
                    &serde_json::json!({
                        "name": "hot cpu",
                        "enable": true,
                        "trigger_mode": 1,
                        "rules": [{
                            "type": "cpu",
                            "max": 50,
                            "duration": 1,
                            "cover": 0
                        }],
                        "fail_trigger_tasks": [cron.id]
                    }),
                )
                .unwrap();
            stored.id
        };
        let (tx, mut rx) = mpsc::channel(1);
        state.task_senders.write().await.insert(server_id, tx);
        let mut runtime = AlertRuntime::default();

        tick_alerts(&state, &mut runtime).await.unwrap();

        let task = rx.recv().await.expect("alert trigger task");
        assert_eq!(task.r#type, TaskType::Command.as_u64());
        assert_eq!(task.data, "echo alert");
    }

    #[tokio::test]
    async fn alert_tick_publishes_cycle_transfer_stats_from_runtime_sentinel() {
        let state = Arc::new(crate::DashboardState::new_for_test());
        let mut runtime = AlertRuntime::default();
        {
            let store = state.store.lock().unwrap();
            let uuid = uuid::Uuid::new_v4();
            let stored = store.ensure_server_for_user(uuid, 0).unwrap();
            store
                .update_state_for_user(
                    uuid,
                    0,
                    nezha_proto::State {
                        net_in_transfer: 100,
                        net_out_transfer: 50,
                        ..Default::default()
                    },
                )
                .unwrap();
            store
                .update_state_for_user(
                    uuid,
                    0,
                    nezha_proto::State {
                        net_in_transfer: 130,
                        net_out_transfer: 70,
                        ..Default::default()
                    },
                )
                .unwrap();
            let cycle_start = Utc
                .timestamp_opt(unix_now().saturating_sub(3600) as i64, 0)
                .single()
                .unwrap()
                .to_rfc3339();
            store
                .upsert_alert_rule(
                    None,
                    0,
                    &serde_json::json!({
                        "name": "monthly traffic",
                        "enable": true,
                        "rules": [{
                            "type": "transfer_all_cycle",
                            "max": 500,
                            "min": 10,
                            "cycle_start": cycle_start,
                            "cycle_interval": 1,
                            "cycle_unit": "hour",
                            "cover": 0
                        }]
                    }),
                )
                .unwrap();
            assert_eq!(stored.id, 1);
        }

        tick_alerts(&state, &mut runtime).await.unwrap();

        let stats = state.cycle_transfer_stats.read().await.clone();
        let item = stats.get(&1).unwrap();
        assert_eq!(item.name, "monthly traffic");
        assert_eq!(item.max, 500);
        assert_eq!(item.min, 10);
        assert_eq!(item.transfer.get(&1), Some(&200));
        assert!(item.next_update.contains_key(&1));
    }

    #[test]
    fn offline_rule_fails_without_thresholds_after_duration() {
        let store = Store::open(":memory:").unwrap();
        let server = store
            .ensure_server_for_user(uuid::Uuid::new_v4(), 0)
            .unwrap();
        let public = store
            .list_servers()
            .unwrap()
            .into_iter()
            .find(|item| item.id == server.id)
            .unwrap();
        let alert = AlertRuleResource {
            id: 1,
            user_id: 0,
            name: "offline".into(),
            enable: Some(true),
            trigger_mode: 1,
            notification_group_id: 0,
            rules: vec![serde_json::json!({
                "type": "offline",
                "duration": 2,
                "cover": 0
            })],
            fail_trigger_tasks: Vec::new(),
            recover_trigger_tasks: Vec::new(),
            created_at: 0,
            updated_at: 0,
        };
        let now = public.last_active.saturating_add(7);
        let mut runtime = AlertRuntime::default();
        let first = alert_snapshot(&alert, &public, &store, now, &mut runtime, None);
        let second = alert_snapshot(&alert, &public, &store, now + 3, &mut runtime, None);

        assert!(!first[0]);
        assert_eq!(alert_check(&alert, &[first]).1, true);
        assert_eq!(alert_check(&alert, &[second.clone(), second]).1, false);
    }

    #[test]
    fn cycle_transfer_rule_uses_stored_transfer_totals() {
        let store = Store::open(":memory:").unwrap();
        let uuid = uuid::Uuid::new_v4();
        let server = store.ensure_server_for_user(uuid, 0).unwrap();
        store
            .update_state_for_user(
                uuid,
                0,
                nezha_proto::State {
                    net_in_transfer: 100,
                    net_out_transfer: 50,
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .update_state_for_user(
                uuid,
                0,
                nezha_proto::State {
                    net_in_transfer: 130,
                    net_out_transfer: 70,
                    ..Default::default()
                },
            )
            .unwrap();
        let public = store
            .list_servers()
            .unwrap()
            .into_iter()
            .find(|item| item.id == server.id)
            .unwrap();
        let cycle_start = Utc
            .timestamp_opt(unix_now().saturating_sub(3600) as i64, 0)
            .single()
            .unwrap()
            .to_rfc3339();
        let rule = serde_json::json!({
            "type": "transfer_all_cycle",
            "max": 150,
            "cycle_start": cycle_start,
            "cycle_interval": 1,
            "cycle_unit": "hour",
            "cover": 0
        });

        let mut runtime = AlertRuntime::default();
        assert!(!rule_snapshot(
            1,
            0,
            &rule,
            &public,
            &store,
            unix_now(),
            &mut runtime,
            None,
        ));
    }
}
