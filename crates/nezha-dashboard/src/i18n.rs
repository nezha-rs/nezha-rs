use std::sync::{OnceLock, RwLock};

static LANGUAGE: OnceLock<RwLock<String>> = OnceLock::new();

pub(crate) fn set_language(language: &str) {
    let normalized = normalize_language(language);
    if let Ok(mut current) = LANGUAGE
        .get_or_init(|| RwLock::new("en_US".to_string()))
        .write()
    {
        *current = normalized;
    }
}

pub(crate) fn translate(message: &str) -> String {
    let language = LANGUAGE
        .get_or_init(|| RwLock::new("en_US".to_string()))
        .read()
        .map(|language| language.clone())
        .unwrap_or_else(|_| "en_US".to_string());
    translate_with_language(&language, message).to_string()
}

fn translate_with_language<'a>(language: &str, message: &'a str) -> &'a str {
    match normalize_language(language).as_str() {
        "zh_CN" | "zh_Hans" => zh_cn(message),
        "zh_TW" | "zh_Hant" => zh_tw(message),
        _ => message,
    }
}

fn normalize_language(language: &str) -> String {
    let language = language.trim().replace('-', "_");
    match language.as_str() {
        "zh" | "zh_Hans" | "zh_CN" => "zh_CN".to_string(),
        "zh_Hant" | "zh_TW" | "zh_HK" => "zh_TW".to_string(),
        "" => "en_US".to_string(),
        _ => language,
    }
}

fn zh_cn(message: &str) -> &str {
    match message {
        "permission denied" => "权限不够",
        "unauthorized" => "未授权",
        "provider is required" => "需要提供者",
        "provider not found" => "未找到提供者",
        "operation not permitted" => "不允许该操作",
        "code is required" => "需要 code",
        "oauth2 user not binded yet" => "oauth2 用户仍未绑定",
        "invalid state key" => "不正确的 state key",
        "server not found or not connected" => "服务器未找到或仍未连接",
        "the retry count must be an integer between 1 and 10" => {
            "重试次数必须为大于 1 且不超过 10 的整数"
        }
        "incorrect username or password" => "用户名或密码错误",
        "incorrect password" => "密码错误",
        "can't delete yourself" => "不能删除自己",
        "server not found" => "服务器未找到",
        "user not found" => "用户未找到",
        "resource not found" => "资源未找到",
        "notification not found" => "通知方式未找到",
        "cron not found" => "计划任务未找到",
        "nat not found" => "NAT 配置未找到",
        "service not found" => "服务未找到",
        "ddns profile not found" => "DDNS 配置未找到",
        "alert rule not found" => "告警规则未找到",
        "stream not found" => "流未找到",
        "invalid server id" => "服务器 ID 无效",
        "user id is required" => "需要用户 ID",
        "real ip header not found" => "未找到真实 IP 请求头",
        "store lock poisoned" => "存储锁已损坏",
        "404 Not Found" => "404 未找到",
        _ => message,
    }
}

fn zh_tw(message: &str) -> &str {
    match message {
        "permission denied" => "權限不足",
        "unauthorized" => "未授權",
        "provider is required" => "需要提供者",
        "provider not found" => "找不到提供者",
        "operation not permitted" => "不允許此操作",
        "code is required" => "需要 code",
        "oauth2 user not binded yet" => "oauth2 使用者尚未綁定",
        "invalid state key" => "不正確的 state key",
        "server not found or not connected" => "伺服器未找到或尚未連線",
        "the retry count must be an integer between 1 and 10" => {
            "重試次數必須為大於 1 且不超過 10 的整數"
        }
        "incorrect username or password" => "使用者名稱或密碼錯誤",
        "incorrect password" => "密碼錯誤",
        "can't delete yourself" => "不能刪除自己",
        "server not found" => "找不到伺服器",
        "user not found" => "找不到使用者",
        "resource not found" => "找不到資源",
        "notification not found" => "找不到通知方式",
        "cron not found" => "找不到排程任務",
        "nat not found" => "找不到 NAT 設定",
        "service not found" => "找不到服務",
        "ddns profile not found" => "找不到 DDNS 設定",
        "alert rule not found" => "找不到告警規則",
        "stream not found" => "找不到串流",
        "invalid server id" => "伺服器 ID 無效",
        "user id is required" => "需要使用者 ID",
        "real ip header not found" => "找不到真實 IP 請求頭",
        "store lock poisoned" => "儲存鎖已損壞",
        "404 Not Found" => "404 找不到",
        _ => message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_common_upstream_messages() {
        assert_eq!(
            translate_with_language("zh_CN", "permission denied"),
            "权限不够"
        );
        assert_eq!(
            translate_with_language("zh-CN", "provider not found"),
            "未找到提供者"
        );
        assert_eq!(
            translate_with_language("zh_TW", "invalid state key"),
            "不正確的 state key"
        );
        assert_eq!(
            translate_with_language("en_US", "permission denied"),
            "permission denied"
        );
    }
}
