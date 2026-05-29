#[cfg(target_os = "linux")]
use std::path::Path;
use std::{
    collections::HashSet,
    process::{Command, Stdio},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

use nezha_core::AgentConfig;
use nezha_proto::{Host, State, StateSensorTemperature};
use sysinfo::{Components, Disks, Networks, System};

pub struct Monitor {
    system: System,
    disks: Disks,
    networks: Networks,
    components: Components,
    disk_allowlist: HashSet<String>,
    nic_allowlist: HashSet<String>,
    collect_temperature: bool,
    collect_gpu: bool,
    skip_connection_count: bool,
    skip_procs_count: bool,
    last_network_refresh: Instant,
}

impl Monitor {
    pub fn new(cfg: &AgentConfig) -> Self {
        Self {
            system: System::new_all(),
            disks: Disks::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
            components: if cfg.temperature {
                Components::new_with_refreshed_list()
            } else {
                Components::new()
            },
            disk_allowlist: cfg
                .hard_drive_partition_allowlist
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            nic_allowlist: cfg
                .nic_allowlist
                .iter()
                .filter_map(|(name, enabled)| enabled.then(|| name.to_ascii_lowercase()))
                .collect(),
            collect_temperature: cfg.temperature,
            collect_gpu: cfg.gpu,
            skip_connection_count: cfg.skip_connection_count,
            skip_procs_count: cfg.skip_procs_count,
            last_network_refresh: Instant::now(),
        }
    }

    pub fn host(&mut self) -> Host {
        self.system.refresh_all();
        self.disks.refresh(true);

        Host {
            platform: System::name().unwrap_or_default(),
            platform_version: System::long_os_version()
                .or_else(System::kernel_version)
                .unwrap_or_default(),
            cpu: self
                .system
                .cpus()
                .iter()
                .map(|cpu| cpu.brand().to_string())
                .collect(),
            mem_total: self.system.total_memory(),
            disk_total: self.disk_totals().0,
            swap_total: self.system.total_swap(),
            arch: System::cpu_arch(),
            virtualization: virtualization_system().unwrap_or_default(),
            boot_time: System::boot_time(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            gpu: if self.collect_gpu {
                gpu_models()
            } else {
                Vec::new()
            },
        }
    }

    pub fn state(&mut self) -> State {
        self.system.refresh_all();
        self.disks.refresh(true);

        let now = Instant::now();
        let elapsed = now
            .duration_since(self.last_network_refresh)
            .as_secs()
            .max(1);
        self.networks.refresh(true);
        self.last_network_refresh = now;

        let (net_in_transfer, net_out_transfer, net_in_speed, net_out_speed) =
            self.network_totals(elapsed);
        let load = System::load_average();
        let (tcp_conn_count, udp_conn_count) = if self.skip_connection_count {
            (0, 0)
        } else {
            connection_counts()
        };
        let process_count = if self.skip_procs_count {
            0
        } else {
            self.system.processes().len() as u64
        };

        State {
            cpu: self.system.global_cpu_usage() as f64,
            mem_used: self.system.used_memory(),
            swap_used: self.system.used_swap(),
            disk_used: self.disk_totals().1,
            net_in_transfer,
            net_out_transfer,
            net_in_speed,
            net_out_speed,
            uptime: System::uptime(),
            load1: load.one,
            load5: load.five,
            load15: load.fifteen,
            tcp_conn_count,
            udp_conn_count,
            process_count,
            temperatures: self.temperatures(),
            gpu: if self.collect_gpu {
                gpu_usage()
            } else {
                Vec::new()
            },
        }
    }

    fn disk_totals(&self) -> (u64, u64) {
        self.disks
            .iter()
            .filter(|disk| {
                self.disk_allowlist.is_empty()
                    || self.disk_allowlist.contains(
                        &disk
                            .mount_point()
                            .to_string_lossy()
                            .to_string()
                            .to_ascii_lowercase(),
                    )
            })
            .fold((0, 0), |(total, used), disk| {
                let disk_total = disk.total_space();
                let disk_used = disk_total.saturating_sub(disk.available_space());
                (total + disk_total, used + disk_used)
            })
    }

    fn network_totals(&self, elapsed_secs: u64) -> (u64, u64, u64, u64) {
        let elapsed = elapsed_secs.max(1);
        let (rx_total, tx_total, rx_bytes, tx_bytes) = self
            .networks
            .iter()
            .filter(|(name, _)| {
                self.nic_allowlist.is_empty()
                    || self.nic_allowlist.contains(&name.to_ascii_lowercase())
            })
            .fold(
                (0u64, 0u64, 0u64, 0u64),
                |(rx_total, tx_total, rx_bytes, tx_bytes), (_, net)| {
                    (
                        rx_total.saturating_add(net.total_received()),
                        tx_total.saturating_add(net.total_transmitted()),
                        rx_bytes.saturating_add(net.received()),
                        tx_bytes.saturating_add(net.transmitted()),
                    )
                },
            );
        (rx_total, tx_total, rx_bytes / elapsed, tx_bytes / elapsed)
    }

    fn temperatures(&mut self) -> Vec<StateSensorTemperature> {
        if !self.collect_temperature {
            return Vec::new();
        }
        self.components.refresh(true);
        let mut temperatures = self
            .components
            .list()
            .iter()
            .filter_map(|component| {
                let name = component.label().trim();
                let temperature = component.temperature()? as f64;
                valid_temperature_sensor(name, temperature).then(|| StateSensorTemperature {
                    name: name.to_string(),
                    temperature,
                })
            })
            .collect::<Vec<_>>();
        temperatures.sort_by(|a, b| a.name.cmp(&b.name));
        temperatures
    }
}

fn valid_temperature_sensor(name: &str, temperature: f64) -> bool {
    temperature.is_finite() && temperature > 0.0 && !matches!(name, "PMU tcal" | "noname" | "")
}

fn virtualization_system() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        return linux_virtualization_guest_system();
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn linux_virtualization_guest_system() -> Option<String> {
    static CACHE: OnceLock<(String, String)> = OnceLock::new();
    let (system, role) = CACHE.get_or_init(linux_virtualization).clone();
    (role == "guest" && !system.is_empty()).then_some(system)
}

#[cfg(target_os = "linux")]
fn linux_virtualization() -> (String, String) {
    linux_virtualization_from_facts(&LinuxVirtualizationFacts::collect())
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct LinuxVirtualizationFacts {
    xen_exists: bool,
    xen_capabilities: Vec<String>,
    modules: Vec<String>,
    cpuinfo: Vec<String>,
    pci_devices: Vec<String>,
    bc_exists: bool,
    vz_exists: bool,
    self_status: Vec<String>,
    pid1_environ: String,
    self_cgroup: Vec<String>,
    os_release_id: String,
    dockerenv_exists: bool,
    lxc_version_exists: bool,
}

#[cfg(target_os = "linux")]
impl LinuxVirtualizationFacts {
    fn collect() -> Self {
        let proc = Path::new("/proc");
        Self {
            xen_exists: proc.join("xen").exists(),
            xen_capabilities: read_lines(proc.join("xen/capabilities")),
            modules: read_lines(proc.join("modules")),
            cpuinfo: read_lines(proc.join("cpuinfo")),
            pci_devices: read_lines(proc.join("bus/pci/devices")),
            bc_exists: proc.join("bc/0").exists(),
            vz_exists: proc.join("vz").exists(),
            self_status: read_lines(proc.join("self/status")),
            pid1_environ: read_file(proc.join("1/environ")),
            self_cgroup: read_lines(proc.join("self/cgroup")),
            os_release_id: os_release_id(Path::new("/etc/os-release")),
            dockerenv_exists: Path::new("/.dockerenv").exists(),
            lxc_version_exists: Path::new("/usr/bin/lxc-version").exists(),
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_virtualization_from_facts(facts: &LinuxVirtualizationFacts) -> (String, String) {
    let mut system = String::new();
    let mut role = String::new();

    if facts.xen_exists {
        system = "xen".to_string();
        role = "guest".to_string();
        if lines_contain(&facts.xen_capabilities, "control_d") {
            role = "host".to_string();
        }
    }

    if !facts.modules.is_empty() {
        if lines_contain(&facts.modules, "kvm") {
            system = "kvm".to_string();
            role = "host".to_string();
        } else if lines_contain(&facts.modules, "hv_util") {
            system = "hyperv".to_string();
            role = "guest".to_string();
        } else if lines_contain(&facts.modules, "vboxdrv") {
            system = "vbox".to_string();
            role = "host".to_string();
        } else if lines_contain(&facts.modules, "vboxguest") {
            system = "vbox".to_string();
            role = "guest".to_string();
        } else if lines_contain(&facts.modules, "vmware") {
            system = "vmware".to_string();
            role = "guest".to_string();
        }
    }

    if !facts.cpuinfo.is_empty()
        && (lines_contain(&facts.cpuinfo, "QEMU Virtual CPU")
            || lines_contain(&facts.cpuinfo, "Common KVM processor")
            || lines_contain(&facts.cpuinfo, "Common 32-bit KVM processor"))
    {
        system = "kvm".to_string();
        role = "guest".to_string();
    }

    if !facts.pci_devices.is_empty() && lines_contain(&facts.pci_devices, "virtio-pci") {
        role = "guest".to_string();
    }

    if facts.bc_exists {
        system = "openvz".to_string();
        role = "host".to_string();
    } else if facts.vz_exists {
        system = "openvz".to_string();
        role = "guest".to_string();
    }

    if !facts.self_status.is_empty()
        && (lines_contain(&facts.self_status, "s_context:")
            || lines_contain(&facts.self_status, "VxID:"))
    {
        system = "linux-vserver".to_string();
    }

    if facts.pid1_environ.contains("container=lxc") {
        system = "lxc".to_string();
        role = "guest".to_string();
    }

    if !facts.self_cgroup.is_empty() {
        if lines_contain(&facts.self_cgroup, "lxc") {
            system = "lxc".to_string();
            role = "guest".to_string();
        } else if lines_contain(&facts.self_cgroup, "docker") {
            system = "docker".to_string();
            role = "guest".to_string();
        } else if lines_contain(&facts.self_cgroup, "machine-rkt") {
            system = "rkt".to_string();
            role = "guest".to_string();
        } else if facts.lxc_version_exists {
            system = "lxc".to_string();
            role = "host".to_string();
        }
    }

    if facts.os_release_id == "coreos" {
        system = "rkt".to_string();
        role = "host".to_string();
    }

    if facts.dockerenv_exists {
        system = "docker".to_string();
        role = "guest".to_string();
    }

    (system, role)
}

#[cfg(target_os = "linux")]
fn read_lines(path: impl AsRef<Path>) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|raw| raw.lines().map(|line| line.to_string()).collect())
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn read_file(path: impl AsRef<Path>) -> String {
    std::fs::read(path)
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn os_release_id(path: &Path) -> String {
    read_lines(path)
        .into_iter()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key == "ID").then(|| value.trim_matches('"').to_string())
        })
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn lines_contain(lines: &[String], needle: &str) -> bool {
    lines.iter().any(|line| line.contains(needle))
}

const GPU_CACHE_TTL: Duration = Duration::from_secs(5);
static GPU_MODELS_CACHE: OnceLock<Mutex<Option<(Instant, Vec<String>)>>> = OnceLock::new();
static GPU_USAGE_CACHE: OnceLock<Mutex<Option<(Instant, Vec<f64>)>>> = OnceLock::new();

fn cached_or_sample<T: Clone>(
    cache: &OnceLock<Mutex<Option<(Instant, T)>>>,
    sampler: impl FnOnce() -> T,
) -> T {
    let cell = cache.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cell.lock() {
        if let Some((ts, value)) = guard.as_ref() {
            if ts.elapsed() < GPU_CACHE_TTL {
                return value.clone();
            }
        }
    }
    let sampled = sampler();
    if let Ok(mut guard) = cell.lock() {
        *guard = Some((Instant::now(), sampled.clone()));
    }
    sampled
}

fn gpu_models() -> Vec<String> {
    cached_or_sample(&GPU_MODELS_CACHE, sample_gpu_models)
}

fn sample_gpu_models() -> Vec<String> {
    nvidia_smi_xml()
        .map(|raw| parse_nvidia_models(&raw))
        .filter(|items| !items.is_empty())
        .or_else(|| {
            rocm_smi_json()
                .map(|raw| parse_rocm_models(&raw))
                .filter(|items| !items.is_empty())
        })
        .or_else(|| platform_gpu_models().filter(|items| !items.is_empty()))
        .unwrap_or_default()
}

fn gpu_usage() -> Vec<f64> {
    cached_or_sample(&GPU_USAGE_CACHE, sample_gpu_usage)
}

fn sample_gpu_usage() -> Vec<f64> {
    nvidia_smi_xml()
        .map(|raw| parse_nvidia_usage(&raw))
        .filter(|items| !items.is_empty())
        .or_else(|| {
            rocm_smi_json()
                .map(|raw| parse_rocm_usage(&raw))
                .filter(|items| !items.is_empty())
        })
        .or_else(|| intel_gpu_top_usage().map(|usage| vec![usage]))
        .or_else(platform_gpu_usage)
        .unwrap_or_default()
}

fn nvidia_smi_xml() -> Option<String> {
    run_command_output("nvidia-smi", &["-q", "-x"], Duration::from_secs(5))
}

fn rocm_smi_json() -> Option<String> {
    run_command_output(
        rocm_smi_binary(),
        &["-u", "--showproductname", "--json"],
        Duration::from_secs(5),
    )
}

fn rocm_smi_binary() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        if std::path::Path::new("/opt/rocm/bin/rocm-smi").exists() {
            return "/opt/rocm/bin/rocm-smi";
        }
    }
    "rocm-smi"
}

fn intel_gpu_top_usage() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        let raw = run_command_output(
            "intel_gpu_top",
            &["-s", "1000", "-l"],
            Duration::from_secs(3),
        )?;
        return parse_intel_gpu_top_usage(&raw);
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "windows")]
fn platform_gpu_models() -> Option<Vec<String>> {
    let raw = run_command_output(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_VideoController | ForEach-Object { $_.Name }",
        ],
        Duration::from_secs(5),
    )?;
    Some(parse_nonempty_lines(&raw))
}

#[cfg(target_os = "macos")]
fn platform_gpu_models() -> Option<Vec<String>> {
    let raw = run_command_output(
        "system_profiler",
        &["SPDisplaysDataType"],
        Duration::from_secs(8),
    )?;
    Some(parse_macos_gpu_models(&raw))
}

#[cfg(target_os = "linux")]
fn platform_gpu_models() -> Option<Vec<String>> {
    let raw = run_command_output("lspci", &["-mm"], Duration::from_secs(5))?;
    Some(parse_lspci_gpu_models(&raw))
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn platform_gpu_models() -> Option<Vec<String>> {
    None
}

#[cfg(target_os = "windows")]
fn platform_gpu_usage() -> Option<Vec<f64>> {
    let raw = run_command_output(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "(Get-Counter '\\GPU Engine(*engtype_3D)\\Utilization Percentage').CounterSamples | Measure-Object -Property CookedValue -Sum | Select-Object -ExpandProperty Sum",
        ],
        Duration::from_secs(5),
    )?;
    let value = parse_first_float(&raw)?.clamp(0.0, 100.0);
    Some(vec![value])
}

#[cfg(target_os = "macos")]
fn platform_gpu_usage() -> Option<Vec<f64>> {
    let raw = run_command_output(
        "ioreg",
        &["-r", "-c", "IOAccelerator", "-d", "1"],
        Duration::from_secs(5),
    )?;
    parse_macos_gpu_usage(&raw).map(|usage| vec![usage])
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn platform_gpu_usage() -> Option<Vec<f64>> {
    None
}

fn parse_nvidia_models(raw: &str) -> Vec<String> {
    xml_tag_values(raw, "product_name")
}

fn parse_nvidia_usage(raw: &str) -> Vec<f64> {
    xml_tag_values(raw, "gpu_util")
        .into_iter()
        .filter_map(|value| parse_first_float(&value))
        .collect()
}

fn parse_rocm_models(raw: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    let Some(map) = value.as_object() else {
        return Vec::new();
    };
    map.values()
        .filter_map(|card| card.get("Card series").and_then(|value| value.as_str()))
        .filter(|name| !name.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_rocm_usage(raw: &str) -> Vec<f64> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    let Some(map) = value.as_object() else {
        return Vec::new();
    };
    map.values()
        .filter_map(|card| card.get("GPU use (%)").and_then(|value| value.as_f64()))
        .collect()
}

#[cfg(any(target_os = "linux", test))]
fn parse_intel_gpu_top_usage(raw: &str) -> Option<f64> {
    let mut header1 = "";
    let mut engines = Vec::new();
    let mut pre_engine_cols = 0_usize;
    let mut skipped_first = false;

    for line in raw.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if line.starts_with("Freq") {
            header1 = line;
            continue;
        }
        if line.starts_with("req") {
            (engines, pre_engine_cols) = parse_intel_gpu_top_headers(header1, line);
            continue;
        }
        if engines.is_empty() {
            continue;
        }
        if !skipped_first {
            skipped_first = true;
            continue;
        }
        if let Some(usage) = parse_intel_gpu_top_row(line, engines.len(), pre_engine_cols) {
            return Some(usage);
        }
    }
    None
}

#[cfg(any(target_os = "linux", test))]
fn parse_intel_gpu_top_headers(header1: &str, header2: &str) -> (Vec<String>, usize) {
    let engines = header1
        .split_whitespace()
        .filter_map(|column| {
            let key = column.trim_end_matches(|ch: char| ch.is_ascii_digit() || ch == '/');
            matches!(key, "RCS" | "BCS" | "VCS" | "VECS" | "CCS").then(|| key.to_string())
        })
        .collect::<Vec<_>>();
    let h2 = header2.split_whitespace().collect::<Vec<_>>();
    let pre_engine_cols = h2
        .iter()
        .position(|column| *column == "gpu")
        .unwrap_or_else(|| {
            if engines.is_empty() {
                0
            } else {
                h2.len().saturating_sub(3 * engines.len())
            }
        });
    (engines, pre_engine_cols)
}

#[cfg(any(target_os = "linux", test))]
fn parse_intel_gpu_top_row(line: &str, engine_count: usize, pre_engine_cols: usize) -> Option<f64> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let need = pre_engine_cols.checked_add(3 * engine_count)?;
    if fields.len() < need {
        return None;
    }
    (0..engine_count)
        .filter_map(|index| fields.get(pre_engine_cols + 3 * index)?.parse::<f64>().ok())
        .max_by(|a, b| a.total_cmp(b))
}

#[cfg(target_os = "macos")]
fn parse_macos_gpu_models(raw: &str) -> Vec<String> {
    raw.lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("Chipset Model:")
                .or_else(|| line.strip_prefix("Model:"))
                .map(str::trim)
        })
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(target_os = "macos")]
fn parse_macos_gpu_usage(raw: &str) -> Option<f64> {
    raw.lines()
        .find_map(|line| line.split_once("\"Device Utilization %\""))
        .and_then(|(_, value)| parse_first_float(value))
        .map(|value| value.clamp(0.0, 100.0))
}

#[cfg(target_os = "linux")]
fn parse_lspci_gpu_models(raw: &str) -> Vec<String> {
    raw.lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("vga compatible controller")
                || lower.contains("3d controller")
                || lower.contains("display controller")
        })
        .filter_map(parse_lspci_model)
        .collect()
}

#[cfg(target_os = "linux")]
fn parse_lspci_model(line: &str) -> Option<String> {
    let fields = parse_lspci_quoted_fields(line);
    match fields.as_slice() {
        [_, _, vendor, model, ..] => Some(format!("{vendor} {model}")),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn parse_lspci_quoted_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            if in_quote {
                fields.push(std::mem::take(&mut current));
            }
            in_quote = !in_quote;
        } else if in_quote {
            current.push(ch);
        }
    }
    fields
}

fn xml_tag_values(raw: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut values = Vec::new();
    let mut rest = raw;
    while let Some(start) = rest.find(&open) {
        let value_start = start + open.len();
        let Some(end) = rest[value_start..].find(&close) else {
            break;
        };
        let value = rest[value_start..value_start + end].trim();
        if !value.is_empty() {
            values.push(xml_unescape(value));
        }
        rest = &rest[value_start + end + close.len()..];
    }
    values
}

fn xml_unescape(raw: &str) -> String {
    raw.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn parse_nonempty_lines(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_first_float(raw: &str) -> Option<f64> {
    let mut number = String::new();
    let mut started = false;
    for ch in raw.chars() {
        if ch.is_ascii_digit() || ch == '.' || (!started && (ch == '-' || ch == '+')) {
            started = true;
            number.push(ch);
        } else if started {
            break;
        }
    }
    number.parse().ok()
}

fn run_command_output(command: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let mut child = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().ok()? {
            let output = child.wait_with_output().ok()?;
            return status
                .success()
                .then(|| String::from_utf8(output.stdout).ok())
                .flatten();
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn connection_counts() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        let counts = proc_net_connection_counts();
        if counts != (0, 0) {
            return counts;
        }
    }

    netstat_connection_counts().unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn proc_net_connection_counts() -> (u64, u64) {
    let tcp = count_proc_net_file("/proc/net/tcp") + count_proc_net_file("/proc/net/tcp6");
    let udp = count_proc_net_file("/proc/net/udp") + count_proc_net_file("/proc/net/udp6");
    (tcp, udp)
}

#[cfg(target_os = "linux")]
fn count_proc_net_file(path: &str) -> u64 {
    std::fs::read_to_string(path)
        .map(|raw| count_proc_net_entries(&raw))
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn count_proc_net_entries(raw: &str) -> u64 {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .skip(1)
        .count() as u64
}

fn netstat_connection_counts() -> Option<(u64, u64)> {
    let output = Command::new("netstat").arg("-an").output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Some(parse_netstat_counts(&stdout))
}

fn parse_netstat_counts(raw: &str) -> (u64, u64) {
    raw.lines().fold((0, 0), |(tcp, udp), line| {
        let line = line.trim_start().to_ascii_lowercase();
        if line.starts_with("tcp") {
            (tcp + 1, udp)
        } else if line.starts_with("udp") {
            (tcp, udp + 1)
        } else {
            (tcp, udp)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_net_counter_ignores_header_and_blank_lines() {
        let raw = r#"
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 1

   1: 00000000:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 2
"#;

        assert_eq!(count_proc_net_entries(raw), 2);
    }

    #[test]
    fn netstat_counter_handles_windows_and_unix_shapes() {
        let raw = r#"
  Proto  Local Address          Foreign Address        State
  TCP    127.0.0.1:5354         127.0.0.1:49701        ESTABLISHED
  TCP6   [::1]:5354             [::1]:49702            ESTABLISHED
  UDP    0.0.0.0:5353           *:*
  udp6       0      0  *.5353                 *.*
"#;

        assert_eq!(parse_netstat_counts(raw), (2, 2));
    }

    #[test]
    fn state_respects_skip_count_flags() {
        let mut monitor = Monitor::new(&AgentConfig {
            skip_connection_count: true,
            skip_procs_count: true,
            ..AgentConfig::default()
        });
        let state = monitor.state();

        assert_eq!(state.tcp_conn_count, 0);
        assert_eq!(state.udp_conn_count, 0);
        assert_eq!(state.process_count, 0);
    }

    #[test]
    fn temperature_sensor_filter_matches_upstream_rules() {
        assert!(valid_temperature_sensor("cpu", 42.0));
        assert!(!valid_temperature_sensor("cpu", 0.0));
        assert!(!valid_temperature_sensor("cpu", f64::NAN));
        assert!(!valid_temperature_sensor("PMU tcal", 42.0));
        assert!(!valid_temperature_sensor("noname", 42.0));
        assert!(!valid_temperature_sensor("", 42.0));
    }

    #[test]
    fn temperature_collection_is_disabled_by_default() {
        let mut monitor = Monitor::new(&AgentConfig::default());
        assert!(monitor.temperatures().is_empty());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_virtualization_detection_matches_gopsutil_rule_order() {
        let mut facts = LinuxVirtualizationFacts {
            modules: vec!["hv_util 0 0 - Live 0x0".to_string()],
            ..Default::default()
        };
        assert_eq!(
            linux_virtualization_from_facts(&facts),
            ("hyperv".to_string(), "guest".to_string())
        );

        facts.cpuinfo = vec!["model name\t: Common KVM processor".to_string()];
        assert_eq!(
            linux_virtualization_from_facts(&facts),
            ("kvm".to_string(), "guest".to_string())
        );

        facts.modules = vec!["kvm 0 0 - Live 0x0".to_string()];
        assert_eq!(
            linux_virtualization_from_facts(&facts),
            ("kvm".to_string(), "guest".to_string())
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_virtualization_detection_handles_containers_and_hosts_like_gopsutil() {
        let facts = LinuxVirtualizationFacts {
            self_cgroup: vec!["1:name=systemd:/docker/abcdef".to_string()],
            dockerenv_exists: true,
            ..Default::default()
        };
        assert_eq!(
            linux_virtualization_from_facts(&facts),
            ("docker".to_string(), "guest".to_string())
        );

        let facts = LinuxVirtualizationFacts {
            self_cgroup: vec!["1:name=systemd:/".to_string()],
            lxc_version_exists: true,
            ..Default::default()
        };
        assert_eq!(
            linux_virtualization_from_facts(&facts),
            ("lxc".to_string(), "host".to_string())
        );

        let facts = LinuxVirtualizationFacts {
            bc_exists: true,
            ..Default::default()
        };
        assert_eq!(
            linux_virtualization_from_facts(&facts),
            ("openvz".to_string(), "host".to_string())
        );
    }

    #[test]
    fn virtualization_is_disabled_on_non_linux_like_upstream() {
        #[cfg(not(target_os = "linux"))]
        assert_eq!(virtualization_system(), None);
    }

    #[test]
    fn parses_nvidia_smi_xml_models_and_usage() {
        let raw = r#"
<nvidia_smi_log>
  <gpu>
    <product_name>NVIDIA GeForce RTX 4090</product_name>
    <utilization><gpu_util> 42 %</gpu_util></utilization>
  </gpu>
  <gpu>
    <product_name>NVIDIA A100-SXM4-40GB</product_name>
    <utilization><gpu_util>99 %</gpu_util></utilization>
  </gpu>
</nvidia_smi_log>
"#;

        assert_eq!(
            parse_nvidia_models(raw),
            vec!["NVIDIA GeForce RTX 4090", "NVIDIA A100-SXM4-40GB"]
        );
        assert_eq!(parse_nvidia_usage(raw), vec![42.0, 99.0]);
    }

    #[test]
    fn parses_rocm_smi_json_models_and_usage() {
        let raw = r#"
{
  "card0": {
    "Card series": "AMD Radeon RX 7900 XTX",
    "GPU use (%)": 73
  },
  "card1": {
    "Card series": "AMD Instinct MI300",
    "GPU use (%)": 8.5
  }
}
"#;

        assert_eq!(
            parse_rocm_models(raw),
            vec!["AMD Radeon RX 7900 XTX", "AMD Instinct MI300"]
        );
        assert_eq!(parse_rocm_usage(raw), vec![73.0, 8.5]);
    }

    #[test]
    fn parses_intel_gpu_top_text_usage_like_upstream() {
        let raw = r#"
Freq MHz  IRQ RC6   Power     RCS/0   BCS/0   VCS/0
req  act       %     gpu       %       %       %
300  100     0  5.00   0.00    0.00   0.00    0.00   0.00   0.00   0.00   0.00
300  100     0 95.29   0.00    0.00   5.32    0.00   0.00   1.00   0.00   0.00
"#;

        assert_eq!(parse_intel_gpu_top_usage(raw), Some(95.29));
    }

    #[test]
    fn gpu_collection_is_disabled_by_default() {
        let mut monitor = Monitor::new(&AgentConfig::default());
        assert!(monitor.host().gpu.is_empty());
        assert!(monitor.state().gpu.is_empty());
    }
}
