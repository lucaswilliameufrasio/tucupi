//! Local-only synthetic listener. Not an HTTP server for production or a sandbox.
//! Requires the `codex-fixture` feature and accepts only a loopback upstream port.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;
use tucupi::codex_protocol::{ApiKeyCredential, OpenAiTransport};

const MAX_HEADER: usize = 8_192;
const MAX_BODY: usize = 128_000;

fn read_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        if headers.len() >= MAX_HEADER {
            return None;
        }
        stream.read_exact(&mut byte).ok()?;
        headers.push(byte[0]);
    }
    let text = std::str::from_utf8(&headers).ok()?;
    let mut lines = text.split("\r\n");
    if lines.next()? != "POST /v1/responses HTTP/1.1" {
        return None;
    }
    let mut length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return None;
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return None;
            }
            length = Some(value.trim().parse::<usize>().ok()?);
        }
    }
    let length = length?;
    if length > MAX_BODY {
        return None;
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).ok()?;
    Some(body)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    if std::env::var_os("TUCUPI_FIXTURE_VERIFY_CGROUP").is_some() {
        tucupi::codex_supervision::check_current_cgroup_limits()?;
        let expected = std::env::var("TUCUPI_FIXTURE_EXPECTED_CGROUP")
            .map_err(|_| "fixture cgroup identity unavailable")?;
        tucupi::codex_supervision::check_current_cgroup_matches(&expected)?;
    }
    let port = std::env::args()
        .nth(1)
        .ok_or("missing fixture port")?
        .parse()?;
    let transport = OpenAiTransport::loopback_fixture(port)?;
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    println!("{}", listener.local_addr()?.port());
    std::io::stdout().flush()?;
    for incoming in listener.incoming().take(2) {
        let mut stream = incoming?;
        let result = match read_request(&mut stream) {
            Some(body) => {
                let credential = ApiKeyCredential::new(
                    Some(tucupi::config::CodexAuthMode::ApiKey),
                    "synthetic-broker-token",
                )?;
                transport.forward(&body, credential).await
            }
            None => Err("invalid request"),
        };
        let (status, body) = match result {
            Ok(body) => ("200 OK", body),
            Err(_) => ("502 Bad Gateway", Vec::new()),
        };
        write!(stream, "HTTP/1.1 {status}\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
        stream.write_all(&body)?;
    }
    Ok(())
}
