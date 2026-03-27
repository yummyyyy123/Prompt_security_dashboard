use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;
use wasm_bindgen::prelude::*;

type HmacSha256 = Hmac<Sha256>;

// --- Constants & Config ---
const MAX_PAYLOAD_SIZE: usize = 51200; // 50KB
const MAX_JSON_DEPTH: usize = 5;
const REPLAY_WINDOW_SEC: u64 = 300; // 5 minutes

#[wasm_bindgen]
pub struct SecurityResult {
    pub success: bool,
    error: Option<String>,
    data: Option<JsValue>,
}

#[wasm_bindgen]
impl SecurityResult {
    #[wasm_bindgen(getter)]
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Option<JsValue> {
        self.data.clone()
    }
}

// --- Cryptography ---

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[wasm_bindgen]
pub fn verify_supabase_webhook(
    secret: &str,
    signature_header: &str,
    body: &str,
    now_ts_sec: u64,
    event_ts_sec: u64,
) -> bool {
    // 1. Basic checks
    if secret.is_empty() || signature_header.is_empty() || body.len() > MAX_PAYLOAD_SIZE {
        return false;
    }

    // 2. Replay Protection: Reject if event is too old or in the future (> 30s drift)
    if event_ts_sec > now_ts_sec + 30 || now_ts_sec > event_ts_sec + REPLAY_WINDOW_SEC {
        return false;
    }

    // 3. HMAC Verification
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body.as_bytes());
    let expected = mac.finalize().into_bytes();

    let sig_hex = signature_header
        .strip_prefix("sha256=")
        .unwrap_or(signature_header)
        .trim();

    match hex::decode(sig_hex) {
        Ok(received) => constant_time_eq(&received, &expected),
        Err(_) => false,
    }
}

#[wasm_bindgen]
pub fn verify_internal_token(provided: &str, expected: &str) -> bool {
    constant_time_eq(provided.as_bytes(), expected.as_bytes())
}

// --- Validation & Sanitization ---

#[derive(Deserialize)]
struct DatabaseSecurityEvent {
    operation: String,
    table: String,
    user: String,
    timestamp: String,
    old_data: Option<Value>,
    new_data: Option<Value>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    request_id: Option<String>,
    details: Option<Value>,
}

/// Strict whitelist-based sanitization
fn sanitize_value(value: &Value, depth: usize) -> Value {
    if depth > MAX_JSON_DEPTH {
        return Value::String("[DEPTH_EXCEEDED]".to_string());
    }

    match value {
        Value::Null => Value::Null,
        Value::Bool(b) => Value::Bool(*b),
        Value::Number(n) => Value::Number(n.clone()),
        Value::String(s) => {
            // Simple truncation to prevent memory bloat
            if s.len() > 1024 {
                Value::String(format!("{}...", &s[..1021]))
            } else {
                Value::String(s.clone())
            }
        }
        Value::Array(arr) => Value::Array(
            arr.iter()
                .take(100) // Limit array size
                .map(|v| sanitize_value(v, depth + 1))
                .collect(),
        ),
        Value::Object(map) => {
            // WHITELIST approach: Only allowed fields in nested objects
            // For root payloads, we redaction check
            let mut out = Map::new();
            const SENSITIVE_PATTERNS: [&str; 15] = [
                "pass", "token", "secret", "key", "auth", "cred", "priv", "conf", 
                "ssn", "card", "bank", "api", "phone", "email", "address"
            ];

            for (k, v) in map.iter().take(50) { // Limit object keys
                let lk = k.to_lowercase();
                if SENSITIVE_PATTERNS.iter().any(|p| lk.contains(p)) {
                    out.insert(k.clone(), Value::String("[REDACTED]".to_string()));
                } else {
                    out.insert(k.clone(), sanitize_value(v, depth + 1));
                }
            }
            Value::Object(out)
        }
    }
}

#[wasm_bindgen]
pub fn validate_and_sanitize_event(event_json: &str) -> Result<JsValue, JsValue> {
    // 1. Size check
    if event_json.len() > MAX_PAYLOAD_SIZE {
        return Err(JsValue::from_str("Payload size exceeded limit"));
    }

    // 2. Parse JSON
    let event: DatabaseSecurityEvent = serde_json::from_str(event_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid JSON: {}", e)))?;
        
    // 3. Strict Schema Validation
    const ALLOWED_OPERATIONS: [&str; 4] = ["INSERT", "UPDATE", "DELETE", "ERROR"];
    const ALLOWED_TABLES: [&str; 5] = ["prompts", "categories", "user_settings", "security_logs", "blocked_ips"];

    if !ALLOWED_OPERATIONS.contains(&event.operation.as_str()) {
        return Err(JsValue::from_str("Invalid operation"));
    }
    if !ALLOWED_TABLES.contains(&event.table.as_str()) {
        return Err(JsValue::from_str("Table not in whitelist"));
    }
    if event.user.is_empty() || event.timestamp.is_empty() {
        return Err(JsValue::from_str("Missing required fields"));
    }
    if event.request_id.as_ref().map_or(true, |r| r.len() < 8) {
        return Err(JsValue::from_str("Missing or invalid request_id"));
    }

    // 4. Construct sanitized object
    let mut sanitized = Map::new();
    sanitized.insert("operation".to_string(), Value::String(event.operation));
    sanitized.insert("table".to_string(), Value::String(event.table));
    sanitized.insert("user".to_string(), Value::String(event.user));
    sanitized.insert("timestamp".to_string(), Value::String(event.timestamp));
    sanitized.insert("request_id".to_string(), Value::String(event.request_id.unwrap()));
    
    if let Some(ip) = event.ip_address {
        sanitized.insert("ip_address".to_string(), Value::String(ip));
    }
    if let Some(ua) = event.user_agent {
        sanitized.insert("user_agent".to_string(), Value::String(ua));
    }
    
    sanitized.insert("old_data".to_string(), event.old_data.map(|v| sanitize_value(&v, 0)).unwrap_or(Value::Null));
    sanitized.insert("new_data".to_string(), event.new_data.map(|v| sanitize_value(&v, 0)).unwrap_or(Value::Null));
    sanitized.insert("details".to_string(), event.details.map(|v| sanitize_value(&v, 0)).unwrap_or(Value::Null));

    serde_wasm_bindgen::to_value(&Value::Object(sanitized))
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

// --- Rate Limiting ---

#[wasm_bindgen]
pub struct RateLimiter {
    counts: std::collections::HashMap<String, (u32, f64)>, 
}

#[wasm_bindgen]
impl RateLimiter {
    #[wasm_bindgen(constructor)]
    pub fn new() -> RateLimiter {
        RateLimiter {
            counts: std::collections::HashMap::new(),
        }
    }

    /// Returns true if BLOCKED
    pub fn check_rate_limit(&mut self, ip: &str, now_ms: f64) -> bool {
        let window_ms = 60_000.0;
        let max_requests = 100;

        if let Some(record) = self.counts.get_mut(ip) {
            if now_ms > record.1 {
                record.0 = 1;
                record.1 = now_ms + window_ms;
                return false;
            }
            if record.0 >= max_requests {
                return true;
            }
            record.0 += 1;
            return false;
        }

        // Cleanup occasionally to prevent memory leaks
        if self.counts.len() > 10000 {
            self.counts.retain(|_, v| now_ms <= v.1);
        }

        self.counts.insert(ip.to_string(), (1, now_ms + window_ms));
        false
    }
}
