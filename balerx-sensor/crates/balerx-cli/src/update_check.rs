//! Opt-in comparison with the latest stable GitHub release.
//!
//! Nothing in this module opens a socket unless [`run_check`] is called.
//! Tests parse fixtures and never call [`run_check`].

use std::io::Read;
use std::time::Duration;

const RELEASES_URL: &str = "https://api.github.com/repos/wrjewski/balerx/releases/latest";
const NOTES_PREFIX: &str = "https://github.com/wrjewski/balerx/releases/";
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BODY_BYTES: u64 = 256 * 1024;

const UNIX_INSTALL_COMMAND: &str = "curl -fsSL https://raw.githubusercontent.com/wrjewski/balerx/main/install.sh -o install.sh && sh install.sh";
const WINDOWS_INSTALL_COMMAND: &str = r#"Invoke-WebRequest "https://raw.githubusercontent.com/wrjewski/balerx/main/install.ps1" -OutFile install.ps1; powershell -ExecutionPolicy Bypass -File .\install.ps1"#;

/// Public installer one-liner for the given OS.
///
/// `windows == true` is the PowerShell form from the README, including
/// `-ExecutionPolicy Bypass` for that one installer process. `false` is curl/sh.
/// Tests pass both flags so every CI OS covers both variants.
pub(crate) fn install_command(windows: bool) -> &'static str {
    if windows {
        WINDOWS_INSTALL_COMMAND
    } else {
        UNIX_INSTALL_COMMAND
    }
}

fn host_install_command() -> &'static str {
    install_command(cfg!(windows))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Semver {
    major: u64,
    minor: u64,
    patch: u64,
}

impl Semver {
    fn dotted(self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StableRelease {
    version: Semver,
    notes_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedRelease {
    Stable(StableRelease),
    Ignored,
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct CheckJson {
    current: String,
    latest: Option<String>,
    update_available: bool,
    release_url: Option<String>,
    install_command: &'static str,
    message: String,
    ok: bool,
}

struct CheckView {
    lines: Vec<String>,
    json: CheckJson,
}

pub(crate) fn install_instructions() -> String {
    install_instructions_for(cfg!(windows))
}

fn install_instructions_for(windows: bool) -> String {
    format!(
        "\
balerx {version}
This command does not download or replace the binary.
Install a published release from https://github.com/wrjewski/balerx :
  {command}
Pin a release with BALERX_VERSION, for example BALERX_VERSION=0.1.8.
SHA256SUMS is checked always. If cosign is on PATH, the script also verifies the keyless Sigstore bundle.",
        version = env!("CARGO_PKG_VERSION"),
        command = install_command(windows),
    )
}

pub(crate) fn print_install_instructions() {
    println!("{}", install_instructions());
}

pub(crate) fn run_version(check: bool, json: bool) {
    if check {
        run_check(json);
    } else {
        print_version(json);
    }
}

pub(crate) fn run_self_update(check: bool, json: bool) {
    if check {
        run_check(json);
    } else {
        print_install_instructions();
    }
}

fn print_version(json: bool) {
    let current = env!("CARGO_PKG_VERSION");
    if json {
        let body = serde_json::json!({ "current": current });
        println!("{}", json_text(&body));
        return;
    }
    println!("balerx {current}");
}

/// One HTTPS GET. A transport or parse failure prints a message and still exits 0.
fn run_check(json: bool) {
    let current = env!("CARGO_PKG_VERSION");
    let view = match fetch_latest_body() {
        Ok(body) => evaluate(current, &body),
        Err(message) => with_install_command(error_view(current, &message), host_install_command()),
    };
    emit(&view, json);
}

fn emit(view: &CheckView, json: bool) {
    if json {
        println!("{}", json_text(&view.json));
        return;
    }
    for line in &view.lines {
        println!("{line}");
    }
}

fn json_text(value: &impl serde::Serialize) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| {
        "{\"ok\":false,\"message\":\"Could not check for updates: the result could not be encoded.\"}"
            .to_string()
    })
}

fn fetch_latest_body() -> Result<String, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(CHECK_TIMEOUT))
        .https_only(true)
        .user_agent(format!("balerx/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    match agent
        .get(RELEASES_URL)
        .header("Accept", "application/vnd.github+json")
        .call()
    {
        Ok(mut response) => read_limited(&mut response),
        Err(error) => Err(describe_transport_error(&error)),
    }
}

fn read_limited(response: &mut ureq::http::Response<ureq::Body>) -> Result<String, String> {
    let mut body = String::new();
    response
        .body_mut()
        .as_reader()
        .take(MAX_BODY_BYTES)
        .read_to_string(&mut body)
        .map_err(|_| {
            "Could not check for updates: the GitHub response could not be read.".to_string()
        })?;
    Ok(body)
}

fn describe_transport_error(error: &ureq::Error) -> String {
    match error {
        ureq::Error::Timeout(_) => {
            "Could not check for updates: the request timed out after 5 seconds.".to_string()
        }
        ureq::Error::StatusCode(status @ (403 | 429)) => format!(
            "Could not check for updates: GitHub rate limit (HTTP {status}). Try again later."
        ),
        ureq::Error::StatusCode(status) => {
            format!("Could not check for updates: GitHub returned HTTP {status}.")
        }
        ureq::Error::HostNotFound
        | ureq::Error::ConnectionFailed
        | ureq::Error::Io(_)
        | ureq::Error::Tls(_)
        | ureq::Error::Rustls(_)
        | ureq::Error::Pem(_)
        | ureq::Error::ConnectProxyFailed(_)
        | ureq::Error::InvalidProxyUrl => {
            "Could not check for updates: no network connection. balerx keeps working offline."
                .to_string()
        }
        other => format!("Could not check for updates: {other}"),
    }
}

fn parse_stable_semver(raw: &str) -> Option<Semver> {
    let trimmed = raw.trim();
    let without_prefix = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    let (core, _) = without_prefix
        .split_once('+')
        .unwrap_or((without_prefix, ""));
    if core.is_empty() || core.contains('-') {
        return None;
    }
    let mut parts = core.split('.');
    let major = parse_component(parts.next()?)?;
    let minor = parse_component(parts.next()?)?;
    let patch = parse_component(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some(Semver {
        major,
        minor,
        patch,
    })
}

fn parse_component(text: &str) -> Option<u64> {
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.chars().all(|ch| ch.is_ascii_digit())
    {
        return None;
    }
    text.parse().ok()
}

fn parse_latest_release(body: &str) -> ParsedRelease {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return ParsedRelease::Unreadable;
    };
    let Some(object) = value.as_object() else {
        return ParsedRelease::Unreadable;
    };
    if is_true(object, "draft") || is_true(object, "prerelease") {
        return ParsedRelease::Ignored;
    }
    let Some(tag) = object.get("tag_name").and_then(serde_json::Value::as_str) else {
        return ParsedRelease::Unreadable;
    };
    if tag.contains('-') {
        return ParsedRelease::Ignored;
    }
    let Some(version) = parse_stable_semver(tag) else {
        return ParsedRelease::Unreadable;
    };
    let html_url = object.get("html_url").and_then(serde_json::Value::as_str);
    ParsedRelease::Stable(StableRelease {
        version,
        notes_url: notes_url(tag, html_url),
    })
}

fn is_true(object: &serde_json::Map<String, serde_json::Value>, key: &str) -> bool {
    object.get(key).and_then(serde_json::Value::as_bool) == Some(true)
}

fn notes_url(tag: &str, html_url: Option<&str>) -> String {
    if let Some(url) = html_url {
        if url.starts_with(NOTES_PREFIX) {
            return url.to_string();
        }
    }
    format!("https://github.com/wrjewski/balerx/releases/tag/{tag}")
}

fn evaluate(current_raw: &str, body: &str) -> CheckView {
    evaluate_for(current_raw, body, cfg!(windows))
}

fn evaluate_for(current_raw: &str, body: &str, windows: bool) -> CheckView {
    let command = install_command(windows);
    let view = if parse_stable_semver(current_raw).is_none() {
        error_view(
            current_raw,
            "Could not check for updates: this build's version is not a stable release.",
        )
    } else {
        match parse_latest_release(body) {
            ParsedRelease::Unreadable => error_view(
                current_raw,
                "Could not check for updates: the GitHub response was not a release.",
            ),
            ParsedRelease::Ignored => ignored_view(current_raw),
            ParsedRelease::Stable(release) => {
                let current = parse_stable_semver(current_raw).expect("checked above");
                match release.version.cmp(&current) {
                    std::cmp::Ordering::Greater => update_view(current_raw, &release, command),
                    std::cmp::Ordering::Less => ahead_view(current_raw, &release),
                    std::cmp::Ordering::Equal => current_view(current_raw, &release),
                }
            }
        }
    };
    with_install_command(view, command)
}

fn error_view(current: &str, message: &str) -> CheckView {
    view(
        current,
        None,
        None,
        false,
        false,
        message.to_string(),
        vec![message.to_string()],
    )
}

fn ignored_view(current: &str) -> CheckView {
    let message = format!("No stable release was found. You have balerx {current}.");
    view(
        current,
        None,
        None,
        false,
        true,
        message.clone(),
        vec![message],
    )
}

fn ahead_view(current: &str, release: &StableRelease) -> CheckView {
    let latest = release.version.dotted();
    let message = format!("balerx {current} is ahead of the latest release ({latest})");
    view(
        current,
        Some(latest),
        Some(release.notes_url.clone()),
        false,
        true,
        message.clone(),
        vec![message],
    )
}

fn current_view(current: &str, release: &StableRelease) -> CheckView {
    let message = format!("balerx {current} is up to date");
    view(
        current,
        Some(release.version.dotted()),
        Some(release.notes_url.clone()),
        false,
        true,
        message.clone(),
        vec![message],
    )
}

fn update_view(current: &str, release: &StableRelease, command: &'static str) -> CheckView {
    let latest = release.version.dotted();
    let message =
        format!("A new version is available: {latest} (you have {current}). Update: {command}");
    let notes = format!("Release notes: {}", release.notes_url);
    view(
        current,
        Some(latest),
        Some(release.notes_url.clone()),
        true,
        true,
        message.clone(),
        vec![message, notes],
    )
}

fn with_install_command(mut view: CheckView, command: &'static str) -> CheckView {
    view.json.install_command = command;
    view
}

fn view(
    current: &str,
    latest: Option<String>,
    release_url: Option<String>,
    update_available: bool,
    ok: bool,
    message: String,
    lines: Vec<String>,
) -> CheckView {
    CheckView {
        lines,
        json: CheckJson {
            current: current.to_string(),
            latest,
            update_available,
            release_url,
            install_command: host_install_command(),
            message,
            ok,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        describe_transport_error, evaluate, evaluate_for, host_install_command, install_command,
        install_instructions, install_instructions_for, parse_latest_release, parse_stable_semver,
        ParsedRelease,
    };

    fn release_json(tag: &str, draft: bool, prerelease: bool, html_url: &str) -> String {
        serde_json::json!({
            "tag_name": tag,
            "draft": draft,
            "prerelease": prerelease,
            "html_url": html_url,
        })
        .to_string()
    }

    #[test]
    fn semver_orders_numeric_components() {
        let older = parse_stable_semver("0.1.9").expect("older");
        let newer = parse_stable_semver("v0.1.10").expect("newer");
        assert!(newer > older);
        assert!(parse_stable_semver("0.2.0").expect("minor") > newer);
        assert!(
            parse_stable_semver("1.0.0").expect("major")
                > parse_stable_semver("0.9.9").expect("nine")
        );
        assert_eq!(
            parse_stable_semver("V0.1.4+gabcdef"),
            parse_stable_semver("0.1.4")
        );
        assert!(parse_stable_semver("0.1.4-rc.1").is_none());
        assert!(parse_stable_semver("01.2.3").is_none());
        assert!(parse_stable_semver("1.2").is_none());
        assert!(parse_stable_semver("1.2.3.4").is_none());
    }

    #[test]
    fn fixture_reports_a_newer_stable_release() {
        let body = include_str!("../tests/fixtures/github-latest-release.json");
        let view = evaluate("0.1.4", body);
        assert!(view.json.ok);
        assert!(view.json.update_available);
        assert_eq!(view.json.latest.as_deref(), Some("0.1.5"));
        assert_eq!(
            view.json.release_url.as_deref(),
            Some("https://github.com/wrjewski/balerx/releases/tag/v0.1.5")
        );
        assert_eq!(
            view.lines[0],
            format!(
                "A new version is available: 0.1.5 (you have 0.1.4). Update: {}",
                host_install_command()
            )
        );
        assert_eq!(view.json.install_command, host_install_command());
        assert_eq!(
            view.lines[1],
            "Release notes: https://github.com/wrjewski/balerx/releases/tag/v0.1.5"
        );
        assert!(matches!(
            parse_latest_release(body),
            ParsedRelease::Stable(_)
        ));
    }

    #[test]
    fn equal_or_newer_local_versions_are_up_to_date() {
        let same = release_json(
            "v0.1.4",
            false,
            false,
            "https://github.com/wrjewski/balerx/releases/tag/v0.1.4",
        );
        let same_view = evaluate("0.1.4", &same);
        assert!(!same_view.json.update_available);
        assert_eq!(
            same_view.lines,
            vec!["balerx 0.1.4 is up to date".to_string()]
        );

        let older_remote = release_json(
            "0.1.4",
            false,
            false,
            "https://github.com/wrjewski/balerx/releases/tag/v0.1.4",
        );
        let ahead = evaluate("0.1.5", &older_remote);
        assert!(!ahead.json.update_available);
        assert_eq!(
            ahead.lines,
            vec!["balerx 0.1.5 is ahead of the latest release (0.1.4)".to_string()]
        );
    }

    #[test]
    fn drafts_and_prereleases_are_ignored() {
        let notes = "https://github.com/wrjewski/balerx/releases/tag/v9.0.0";
        for body in [
            release_json("v9.0.0", true, false, notes),
            release_json("v9.0.0", false, true, notes),
            release_json("v0.1.5-rc.1", false, false, notes),
        ] {
            let view = evaluate("0.1.4", &body);
            assert!(!view.json.update_available);
            assert!(view.json.ok);
            assert!(view.json.latest.is_none());
            assert_eq!(
                view.lines,
                vec!["No stable release was found. You have balerx 0.1.4.".to_string()]
            );
        }
    }

    #[test]
    fn unreadable_responses_and_foreign_urls_are_safe() {
        let broken = evaluate("0.1.4", "not-json");
        assert!(!broken.json.ok);
        assert_eq!(
            broken.lines[0],
            "Could not check for updates: the GitHub response was not a release."
        );

        let foreign = release_json("v0.1.5", false, false, "https://evil.example/phish");
        let view = evaluate("0.1.4", &foreign);
        assert_eq!(
            view.json.release_url.as_deref(),
            Some("https://github.com/wrjewski/balerx/releases/tag/v0.1.5")
        );
        assert!(!view.lines[1].contains("evil.example"));
    }

    #[test]
    fn transport_errors_name_timeout_rate_limit_and_offline() {
        let timeout = describe_transport_error(&ureq::Error::Timeout(ureq::Timeout::Global));
        assert!(timeout.contains("timed out after 5 seconds"));
        let limited = describe_transport_error(&ureq::Error::StatusCode(429));
        assert!(limited.contains("rate limit"));
        assert!(limited.contains("429"));
        let forbidden = describe_transport_error(&ureq::Error::StatusCode(403));
        assert!(forbidden.contains("403"));
        let offline = describe_transport_error(&ureq::Error::HostNotFound);
        assert!(offline.contains("no network connection"));
        let refused = describe_transport_error(&ureq::Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        )));
        assert!(refused.contains("no network connection"));
    }

    #[test]
    fn install_command_selects_unix_and_windows() {
        let unix = install_command(false);
        assert_eq!(
            unix,
            "curl -fsSL https://raw.githubusercontent.com/wrjewski/balerx/main/install.sh -o install.sh && sh install.sh"
        );
        assert!(unix.contains("install.sh"));
        assert!(unix.contains("curl -fsSL"));
        assert!(!unix.contains("install.ps1"));
        assert!(!unix.contains("Invoke-WebRequest"));

        let windows = install_command(true);
        assert_eq!(
            windows,
            r#"Invoke-WebRequest "https://raw.githubusercontent.com/wrjewski/balerx/main/install.ps1" -OutFile install.ps1; powershell -ExecutionPolicy Bypass -File .\install.ps1"#
        );
        assert!(windows.contains("install.ps1"));
        assert!(windows.contains("Invoke-WebRequest"));
        assert!(windows.contains(r"powershell -ExecutionPolicy Bypass -File .\install.ps1"));
        assert!(!windows.contains("install.sh"));
        assert!(!windows.contains("curl"));
        assert!(!windows.contains("-fsSL"));
        assert_ne!(unix, windows);
        assert_eq!(host_install_command(), install_command(cfg!(windows)));
    }

    #[test]
    fn update_message_uses_os_install_command() {
        let body = include_str!("../tests/fixtures/github-latest-release.json");
        let unix = evaluate_for("0.1.4", body, false);
        let windows = evaluate_for("0.1.4", body, true);
        let notes = "Release notes: https://github.com/wrjewski/balerx/releases/tag/v0.1.5";

        assert_eq!(
            unix.lines[0],
            format!(
                "A new version is available: 0.1.5 (you have 0.1.4). Update: {}",
                install_command(false)
            )
        );
        assert_eq!(unix.lines[1], notes);
        assert_eq!(unix.json.install_command, install_command(false));
        assert!(unix.json.update_available);
        assert!(!unix.lines[0].contains("Invoke-WebRequest"));

        assert_eq!(
            windows.lines[0],
            format!(
                "A new version is available: 0.1.5 (you have 0.1.4). Update: {}",
                install_command(true)
            )
        );
        assert_eq!(windows.lines[1], notes);
        assert_eq!(windows.json.install_command, install_command(true));
        assert!(windows.json.update_available);
        assert!(windows.lines[0].contains("Invoke-WebRequest"));
        assert!(windows.lines[0].contains("install.ps1"));
        assert!(!windows.lines[0].contains("install.sh"));
        assert!(!windows.lines[0].contains("-fsSL"));
    }

    #[test]
    fn install_text_stays_offline() {
        let host = install_instructions();
        assert!(host.contains(&format!("  {}", host_install_command())));
        assert!(host.contains("does not download or replace the binary"));
        assert!(!host.contains("api.github.com"));
        assert!(host.starts_with(&format!("balerx {}\n", env!("CARGO_PKG_VERSION"))));

        let unix = install_instructions_for(false);
        assert!(unix.contains(install_command(false)));
        assert!(!unix.contains("install.ps1"));
        assert!(!unix.contains("api.github.com"));

        let windows = install_instructions_for(true);
        assert!(windows.contains(install_command(true)));
        assert!(!windows.contains("install.sh"));
        assert!(!windows.contains("api.github.com"));
    }
}
