//! Explicitly opted-in local-only fixture support; never included by default.

pub fn service() -> Option<String> {
    let value = std::env::var("TUCUPI_REVIEW_PTY_SERVICE").ok()?;
    let suffix = value.strip_prefix("tucupi-pty-")?;
    if suffix.len() < 12 || suffix.len() > 64 || !suffix.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(value)
}

pub fn endpoint() -> Option<String> {
    service()?;
    let port: u16 = std::env::var("TUCUPI_REVIEW_PTY_PORT").ok()?.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some(format!("http://127.0.0.1:{port}/review"))
}
