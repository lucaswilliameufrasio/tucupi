//! Direct, tool-free model API transport for source review.

use crate::secrets::ReviewApiProvider;
use serde_json::{json, Value};
use std::time::Duration;

const MAX_RESPONSE: usize = 128_000;
const MAX_PROMPT: usize = 128_000;

impl ReviewApiProvider {
    fn endpoint(self) -> &'static str {
        match self {
            Self::OpenRouter => "https://openrouter.ai/api/v1/chat/completions",
            Self::OpenAi => "https://api.openai.com/v1/responses",
            Self::Anthropic => "https://api.anthropic.com/v1/messages",
            Self::DeepSeek => "https://api.deepseek.com/chat/completions",
            Self::Zai => "https://api.z.ai/api/paas/v4/chat/completions",
            Self::Kimi => "https://api.moonshot.ai/v1/chat/completions",
        }
    }
}

fn request_body(provider: ReviewApiProvider, model: &str, prompt: &str) -> Option<Value> {
    if model.trim().is_empty()
        || model.len() > 256
        || model.chars().any(char::is_control)
        || prompt.len() > MAX_PROMPT
    {
        return None;
    }
    let body = match provider {
        ReviewApiProvider::OpenAi => json!({
            "model": model, "input": prompt, "store": false,
            "max_output_tokens": 2048
        }),
        ReviewApiProvider::Anthropic => json!({
            "model": model, "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}]
        }),
        ReviewApiProvider::Kimi => json!({
            "model": model, "max_completion_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}], "stream": false
        }),
        _ => json!({
            "model": model, "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}], "stream": false
        }),
    };
    Some(body)
}

fn response_text(provider: ReviewApiProvider, value: &Value) -> Option<&str> {
    match provider {
        ReviewApiProvider::OpenAi => {
            if value.get("status")?.as_str()? != "completed" {
                return None;
            }
            let output = value.get("output")?.as_array()?;
            let mut text = None;
            for item in output {
                match item.get("type")?.as_str()? {
                    "reasoning" => continue,
                    "message" => {
                        if item.get("role")?.as_str()? != "assistant"
                            || item.get("status")?.as_str()? != "completed"
                        {
                            return None;
                        }
                        for part in item.get("content")?.as_array()? {
                            if part.get("type")?.as_str()? != "output_text" || text.is_some() {
                                return None;
                            }
                            text = Some(part.get("text")?.as_str()?);
                        }
                    }
                    _ => return None,
                }
            }
            text
        }
        ReviewApiProvider::Anthropic => {
            if value.get("stop_reason")?.as_str()? != "end_turn" {
                return None;
            }
            let content = value.get("content")?.as_array()?;
            if content.len() != 1 || content[0].get("type")?.as_str()? != "text" {
                return None;
            }
            content[0].get("text")?.as_str()
        }
        _ => {
            let choices = value.get("choices")?.as_array()?;
            if choices.len() != 1 || choices[0].get("finish_reason")?.as_str()? != "stop" {
                return None;
            }
            let message = choices[0].get("message")?;
            if message.get("role")?.as_str()? != "assistant"
                || message.get("tool_calls").is_some_and(|v| !v.is_null())
                || choices[0].get("error").is_some_and(|v| !v.is_null())
            {
                return None;
            }
            message.get("content")?.as_str()
        }
    }
}

/// Fixed HTTPS endpoints, no ambient proxies or redirects; never returns raw
/// upstream errors. The caller must explicitly select a provider and model.
pub async fn request_review(
    provider: ReviewApiProvider,
    model: &str,
    prompt: &str,
    key: &str,
) -> Result<String, &'static str> {
    #[cfg(all(target_os = "linux", feature = "review-pty-fixture"))]
    if let Some(endpoint) = crate::review_pty_fixture::endpoint() {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| "transport unavailable")?;
        return request_with_client(&client, &endpoint, provider, model, prompt, key).await;
    }
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(90))
        .build()
        .map_err(|_| "transport unavailable")?;
    request_with_client(&client, provider.endpoint(), provider, model, prompt, key).await
}

pub(crate) async fn request_with_client(
    client: &reqwest::Client,
    endpoint: &str,
    provider: ReviewApiProvider,
    model: &str,
    prompt: &str,
    key: &str,
) -> Result<String, &'static str> {
    if key.is_empty() || key.len() > 8192 || !key.bytes().all(|b| (33..=126).contains(&b)) {
        return Err("invalid credential");
    }
    let body = request_body(provider, model, prompt).ok_or("invalid request")?;
    let mut request = client.post(endpoint).json(&body);
    if provider == ReviewApiProvider::Anthropic {
        request = request
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01");
    } else {
        request = request.bearer_auth(key);
    }
    let mut response = request.send().await.map_err(|_| "provider unavailable")?;
    if !response.status().is_success() {
        return Err("provider request failed");
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE as u64)
    {
        return Err("provider response too large");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "provider unavailable")? {
        if chunk.len() > MAX_RESPONSE.saturating_sub(bytes.len()) {
            return Err("provider response too large");
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid provider response")?;
    let text = response_text(provider, &value).ok_or("invalid provider response")?;
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn all_providers_have_fixed_https_endpoints_and_tool_free_requests() {
        for provider in ReviewApiProvider::ALL {
            assert!(provider.endpoint().starts_with("https://"));
            let body = request_body(provider, "synthetic-model", "synthetic prompt").unwrap();
            assert!(body.get("tools").is_none());
            assert_eq!(body["model"], "synthetic-model");
        }
    }

    #[test]
    fn responses_must_be_complete_and_without_tools() {
        let chat = json!({"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}]});
        for provider in [
            ReviewApiProvider::OpenRouter,
            ReviewApiProvider::DeepSeek,
            ReviewApiProvider::Zai,
            ReviewApiProvider::Kimi,
        ] {
            assert_eq!(response_text(provider, &chat), Some("ok"));
            let mut incomplete = chat.clone();
            incomplete["choices"][0]["finish_reason"] = json!("length");
            assert_eq!(response_text(provider, &incomplete), None);
            let mut tool = chat.clone();
            tool["choices"][0]["message"]["tool_calls"] = json!([{}]);
            assert_eq!(response_text(provider, &tool), None);
        }
        let openai = json!({"status":"completed","output":[{"type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"ok"}]}]});
        assert_eq!(
            response_text(ReviewApiProvider::OpenAi, &openai),
            Some("ok")
        );
        let anthropic = json!({"stop_reason":"end_turn","content":[{"type":"text","text":"ok"}]});
        assert_eq!(
            response_text(ReviewApiProvider::Anthropic, &anthropic),
            Some("ok")
        );
        let truncated = json!({"stop_reason":"max_tokens","content":[{"type":"text","text":"ok"}]});
        assert_eq!(
            response_text(ReviewApiProvider::Anthropic, &truncated),
            None
        );
    }

    #[tokio::test]
    async fn real_client_sends_provider_specific_requests_to_local_fixture() {
        for provider in ReviewApiProvider::ALL {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 4096];
                loop {
                    let count = stream.read(&mut buffer).unwrap();
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]);
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
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let response = match provider {
                    ReviewApiProvider::OpenAi => json!({"status":"completed","output":[{"type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"ok"}]}]}),
                    ReviewApiProvider::Anthropic => json!({"stop_reason":"end_turn","content":[{"type":"text","text":"ok"}]}),
                    _ => json!({"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}]}),
                }.to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
                request
            });
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            let result = request_with_client(
                &client,
                &format!("http://{address}/review"),
                provider,
                "synthetic-model",
                "synthetic prompt",
                "synthetic-key",
            )
            .await;
            assert_eq!(result, Ok("ok".into()));
            let request = server.join().unwrap();
            let request = String::from_utf8(request).unwrap();
            let request_lower = request.to_ascii_lowercase();
            if provider == ReviewApiProvider::Anthropic {
                assert!(request_lower.contains("x-api-key: synthetic-key"));
                assert!(request_lower.contains("anthropic-version: 2023-06-01"));
            } else {
                assert!(request_lower.contains("authorization: bearer synthetic-key"));
            }
            assert!(request.contains("synthetic prompt"));
            assert!(!request.contains("\"tools\""));
        }
    }
}
