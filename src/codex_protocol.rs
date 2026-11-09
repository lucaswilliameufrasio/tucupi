//! Experimental protocol validation and fixed-endpoint transport. This module
//! is not wired to a provider and does not establish a security sandbox.

use serde_json::Value;

const LIMIT: usize = 128_000;
const API_KEY_LIMIT: usize = 8192;

/// Borrowed API-key intent; this does not verify credential provenance or
/// authorize execution or identify the supplied secret. ChatGPT mode is rejected.
pub struct ApiKeyCredential<'a>(&'a str);

impl<'a> ApiKeyCredential<'a> {
    pub fn new(
        mode: Option<crate::config::CodexAuthMode>,
        value: &'a str,
    ) -> Result<Self, &'static str> {
        if mode != Some(crate::config::CodexAuthMode::ApiKey)
            || value.is_empty()
            || value.len() > API_KEY_LIMIT
        {
            return Err("invalid API-key authentication");
        }
        // RFC 6750 b64token: ASCII token characters followed only by optional
        // padding. Validation does not prove the key is valid or authorized.
        let mut padding = false;
        let mut token_characters = 0usize;
        for byte in value.bytes() {
            if byte == b'=' {
                padding = true;
            } else if !padding
                && (byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/'))
            {
                token_characters += 1;
            } else {
                return Err("invalid API-key authentication");
            }
        }
        if token_characters == 0 {
            return Err("invalid API-key authentication");
        }
        Ok(Self(value))
    }
}

/// Experimental API-key transport, not an isolated worker or an authentication
/// manager. Codex remains disabled until the surrounding boundary is verified.
pub struct OpenAiTransport {
    client: reqwest::Client,
    endpoint: String,
}

impl OpenAiTransport {
    /// Local synthetic fixture only. This is not an authentication or sandbox boundary.
    #[cfg(feature = "codex-fixture")]
    pub fn loopback_fixture(port: u16) -> Result<Self, &'static str> {
        if port == 0 {
            return Err("invalid fixture port");
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|_| "transport unavailable")?;
        Ok(Self {
            client,
            endpoint: format!("http://127.0.0.1:{port}/v1/responses"),
        })
    }
    /// Construct a transport pinned to OpenAI's Responses API. Redirects and
    /// inherited proxies are disabled; callers must supply credentials explicitly.
    pub fn new() -> Result<Self, &'static str> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| "transport unavailable")?;
        Ok(Self {
            client,
            endpoint: "https://api.openai.com/v1/responses".into(),
        })
    }

    /// Forward one validated request; failures never yield a partial response.
    /// The credential must remain with the trusted supervisor, not the worker.
    pub async fn forward(
        &self,
        body: &[u8],
        credential: ApiKeyCredential<'_>,
    ) -> Result<Vec<u8>, &'static str> {
        let payload = prepare_request(body).ok_or("invalid request")?;
        let mut response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(credential.0)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|_| "upstream unavailable")?;
        if !response.status().is_success() {
            return Err("upstream failed");
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if !content_type.is_some_and(|value| value.eq_ignore_ascii_case("text/event-stream")) {
            return Err("invalid upstream response");
        }
        if response
            .content_length()
            .is_some_and(|length| length > LIMIT as u64)
        {
            return Err("upstream response too large");
        }
        let mut output = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| "upstream unavailable")? {
            if chunk.len() > LIMIT.saturating_sub(output.len()) {
                return Err("upstream response too large");
            }
            output.extend_from_slice(&chunk);
        }
        if !validate_response(&output) {
            return Err("invalid upstream response");
        }
        Ok(output)
    }
}

impl Default for OpenAiTransport {
    fn default() -> Self {
        Self::new().expect("failed to construct fixed OpenAI transport")
    }
}

fn contains_tool_call(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(contains_tool_call),
        Value::Object(fields) => {
            if fields.get("role").and_then(Value::as_str) == Some("tool") {
                return true;
            }
            if let Some(kind) = fields.get("type") {
                let Some(kind) = kind.as_str() else {
                    return true;
                };
                if kind.contains("tool_call")
                    || kind.contains("function_call")
                    || kind.ends_with("_call")
                    || kind.contains("_call_output")
                {
                    return true;
                }
            }
            fields.values().any(contains_tool_call)
        }
        _ => false,
    }
}

/// Prepare a bounded synthetic Responses API request without tool declarations.
/// It must not be used as a standalone authorization or isolation boundary.
pub fn prepare_request(body: &[u8]) -> Option<Vec<u8>> {
    if body.len() > LIMIT {
        return None;
    }
    let mut value: Value = serde_json::from_slice(body).ok()?;
    let fields = value.as_object_mut()?;
    if fields
        .get("background")
        .is_some_and(|value| value != &Value::Bool(false))
    {
        return None;
    }
    fields.insert("background".into(), Value::Bool(false));
    if fields.get("input").is_some_and(contains_tool_call) {
        return None;
    }
    fields.remove("tools");
    fields.remove("tool_choice");
    let prepared = serde_json::to_vec(&value).ok()?;
    if prepared.len() > LIMIT {
        return None;
    }
    Some(prepared)
}

fn valid_item(item: &Value) -> bool {
    if item.get("type").and_then(Value::as_str) != Some("message")
        || item.get("role").and_then(Value::as_str) != Some("assistant")
    {
        return false;
    }
    match item.get("content") {
        None => true,
        Some(Value::Array(parts)) => parts.iter().all(|part| {
            matches!(
                part.get("type").and_then(Value::as_str),
                Some("output_text" | "refusal")
            )
        }),
        _ => false,
    }
}

/// Accept only a bounded, completed synthetic SSE response without tool calls.
/// Unknown event or output types fail closed; no partial stream is accepted.
pub fn validate_response(body: &[u8]) -> bool {
    if body.len() > LIMIT {
        return false;
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return false;
    };
    let mut completed = false;
    let mut done = false;
    let mut pending_frame = false;
    for line in text.lines() {
        if line.is_empty() {
            pending_frame = false;
            continue;
        }
        if pending_frame || done {
            return false;
        }
        pending_frame = true;
        let Some(data) = line.strip_prefix("data: ") else {
            return false;
        };
        if data == "[DONE]" {
            if !completed {
                return false;
            }
            done = true;
            continue;
        }
        if completed {
            return false;
        }
        let Ok(event) = serde_json::from_str::<Value>(data) else {
            return false;
        };
        if contains_tool_call(&event) {
            return false;
        }
        match event.get("type").and_then(Value::as_str) {
            Some(
                "response.created"
                | "response.in_progress"
                | "response.content_part.added"
                | "response.content_part.done"
                | "response.output_text.delta"
                | "response.output_text.done",
            ) => {}
            Some("response.output_item.added" | "response.output_item.done") => {
                if !event.get("item").is_some_and(valid_item) {
                    return false;
                }
            }
            Some("response.completed") => {
                let Some(response) = event.get("response") else {
                    return false;
                };
                if response.get("status").and_then(Value::as_str) != Some("completed") {
                    return false;
                }
                let Some(output) = response.get("output").and_then(Value::as_array) else {
                    return false;
                };
                if !output.iter().all(valid_item) {
                    return false;
                }
                completed = true;
            }
            _ => return false,
        }
    }
    completed && !pending_frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_transport_requires_explicit_api_key_mode() {
        use crate::config::CodexAuthMode;
        assert!(ApiKeyCredential::new(None, "synthetic-only").is_err());
        assert!(ApiKeyCredential::new(Some(CodexAuthMode::Chatgpt), "synthetic-only").is_err());
        assert!(ApiKeyCredential::new(Some(CodexAuthMode::Invalid), "synthetic-only").is_err());
        assert!(ApiKeyCredential::new(Some(CodexAuthMode::ApiKey), "").is_err());
        assert!(ApiKeyCredential::new(Some(CodexAuthMode::ApiKey), "synthetic\nonly").is_err());
        assert!(ApiKeyCredential::new(Some(CodexAuthMode::ApiKey), "synthetic-only").is_ok());
    }

    #[test]
    fn api_key_credential_rejects_invalid_bearer_syntax_and_oversize() {
        use crate::config::CodexAuthMode;
        for value in [
            " ",
            "synthetic key",
            " synthetic",
            "synthetic\t",
            "é",
            "synthetic=more",
            "===",
        ] {
            assert!(ApiKeyCredential::new(Some(CodexAuthMode::ApiKey), value).is_err());
        }
        assert!(ApiKeyCredential::new(Some(CodexAuthMode::ApiKey), &"a".repeat(8193)).is_err());
        assert!(ApiKeyCredential::new(Some(CodexAuthMode::ApiKey), &"a".repeat(8192)).is_ok());
        assert!(ApiKeyCredential::new(Some(CodexAuthMode::ApiKey), "synthetic-A_1.~+/==").is_ok());
    }

    #[test]
    fn request_strips_tools_and_rejects_tool_calls() {
        let request = br#"{"model":"fixture","input":[{"role":"user","content":"synthetic"}],"tools":[{"type":"function","name":"shell"}],"tool_choice":"auto"}"#;
        let result: Value = serde_json::from_slice(&prepare_request(request).unwrap()).unwrap();
        assert!(result.get("tools").is_none());
        assert!(result.get("tool_choice").is_none());
        assert!(
            prepare_request(br#"{"input":[{"type":"function_call","name":"shell"}]}"#).is_none()
        );
        assert!(prepare_request(&vec![b'x'; LIMIT + 1]).is_none());
    }

    #[test]
    fn request_rejects_background_execution() {
        for value in ["true", "null", "\"false\"", "1"] {
            let body = format!("{{\"input\":\"synthetic\",\"background\":{value}}}");
            assert!(prepare_request(body.as_bytes()).is_none(), "{value}");
        }
        for body in [
            br#"{"input":"synthetic"}"#.as_slice(),
            br#"{"input":"synthetic","background":false}"#.as_slice(),
        ] {
            let value: Value = serde_json::from_slice(&prepare_request(body).unwrap()).unwrap();
            assert_eq!(value.get("background"), Some(&Value::Bool(false)));
        }
    }

    #[test]
    fn response_requires_completed_assistant_messages_without_tools() {
        let valid = b"data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"review\"}]}]}}\n\ndata: [DONE]\n\n";
        assert!(validate_response(valid));
        for kind in [
            "function_call",
            "computer_call",
            "web_search_call",
            "mcp_call",
            "tool_use",
        ] {
            let body = format!("data: {{\"type\":\"response.completed\",\"response\":{{\"status\":\"completed\",\"output\":[{{\"type\":\"{kind}\"}}]}}}}\n\n");
            assert!(!validate_response(body.as_bytes()), "{kind}");
        }
        assert!(!validate_response(b"data: {\"type\":\"response.completed\",\"response\":{\"status\":\"incomplete\",\"output\":[]}}\n\n"));
        assert!(!validate_response(&vec![b'x'; LIMIT + 1]));
    }

    #[test]
    fn response_rejects_truncated_or_misordered_sse_frames() {
        let complete = "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}";
        assert!(!validate_response(complete.as_bytes()));
        assert!(!validate_response(
            format!("data: [DONE]\n\n{complete}\n\n").as_bytes()
        ));
        assert!(!validate_response(
            format!("{complete}\n\ndata: [DONE]\n\ndata: [DONE]\n\n").as_bytes()
        ));
        assert!(validate_response(
            format!("{complete}\n\ndata: [DONE]\n\n").as_bytes()
        ));
    }

    #[tokio::test]
    async fn synthetic_http_service_receives_filtered_request() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Duration;

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 4096];
            let (header_end, length) = loop {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
                assert!(request.len() < LIMIT + 8192);
                if let Some(pos) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&request[..pos]).unwrap();
                    assert!(headers.starts_with("POST /v1/responses HTTP/1.1"));
                    assert!(headers
                        .to_ascii_lowercase()
                        .contains("authorization: bearer synthetic-only"));
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            if name.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap();
                    break (pos + 4, length);
                }
            };
            while request.len() - header_end < length {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
            }
            let payload: Value =
                serde_json::from_slice(&request[header_end..header_end + length]).unwrap();
            assert!(payload.get("tools").is_none());
            assert_eq!(payload.get("background"), Some(&Value::Bool(false)));
            let body = b"data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"VERDICT: review\\nREASON: synthetic\"}]}]}}\n\ndata: [DONE]\n\n";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        let transport = OpenAiTransport {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            endpoint: format!("http://{address}/v1/responses"),
        };
        let response = transport
            .forward(
                br#"{"input":"synthetic","tools":[{"type":"function","name":"shell"}]}"#,
                ApiKeyCredential::new(Some(crate::config::CodexAuthMode::ApiKey), "synthetic-only")
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(validate_response(&response));
        let pending = crate::review::parse_codex_review_response(&response).unwrap();
        #[cfg(not(target_os = "linux"))]
        let _ = pending;
        #[cfg(target_os = "linux")]
        {
            use crate::codex_supervision::{
                CgroupObservation, CgroupSequence, CgroupSequenceState,
            };
            let dir = tempfile::tempdir().unwrap();
            let events = dir.path().join("cgroup.events");
            std::fs::write(&events, "populated 1\n").unwrap();
            let sequence = CgroupSequence::new(CgroupObservation::open(dir.path()).unwrap());
            let mut observed = pending.bind_cgroup(sequence).unwrap();
            std::fs::write(&events, "populated 0\n").unwrap();
            assert_eq!(
                observed.observe_cgroup(),
                Ok(CgroupSequenceState::EmptyAfterPopulated)
            );
            std::fs::write(&events, "populated 1\n").unwrap();
            assert!(observed.observe_cgroup().is_err());
        }
        server.join().unwrap();
    }

    #[tokio::test]
    async fn transport_fails_closed_on_redirects_bad_streams_and_excess() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Duration;

        async fn check(wire: Vec<u8>, expected: &str) {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut buffer = [0; 4096];
                assert!(stream.read(&mut buffer).unwrap() > 0);
                stream.write_all(&wire).unwrap();
            });
            let transport = OpenAiTransport {
                client: reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap(),
                endpoint: format!("http://{address}/v1/responses"),
            };
            assert_eq!(
                transport
                    .forward(
                        br#"{"input":"synthetic"}"#,
                        ApiKeyCredential::new(
                            Some(crate::config::CodexAuthMode::ApiKey),
                            "synthetic-only"
                        )
                        .unwrap()
                    )
                    .await
                    .unwrap_err(),
                expected
            );
            server.join().unwrap();
        }

        check(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/leak\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(), "upstream failed").await;
        let tool = b"data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\"}}\n\n";
        let mut wire = format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", tool.len()).into_bytes();
        wire.extend_from_slice(tool);
        check(wire, "invalid upstream response").await;
        check(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", LIMIT + 1).into_bytes(), "upstream response too large").await;
    }
}
