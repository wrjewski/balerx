use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "balerx-guard-status-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn status(home: &PathBuf, work: &PathBuf, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_balerx"))
        .env("HOME", home)
        .env("USERPROFILE", home)
        .current_dir(work)
        .arg("guard")
        .arg("status")
        .args(extra)
        .output()
        .expect("guard status")
}

#[test]
fn fresh_install_exits_0_and_names_the_install_command() {
    let home = temp_dir("home");
    let work = temp_dir("work");
    let output = status(&home, &work, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "fresh status failed: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("Not installed — run: balerx guard install claude-code"));
    assert!(stdout.contains("Not installed — run: balerx guard install cursor"));
    assert!(stdout.contains("not installed"));

    let strict = status(&home, &work, &["--strict"]);
    assert_eq!(strict.status.code(), Some(1));
    let strict_out = String::from_utf8_lossy(&strict.stdout);
    assert!(strict_out.contains("Not installed — run: balerx guard install claude-code"));

    let check = status(&home, &work, &["--check"]);
    assert_eq!(check.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&check.stdout).contains("balerx guard install cursor"));
}

#[test]
fn installed_hook_exits_0_even_with_strict() {
    let home = temp_dir("hook-home");
    let work = temp_dir("hook-work");
    let hooks = home.join(".cursor").join("hooks.json");
    fs::create_dir_all(hooks.parent().expect("parent")).expect("dir");
    let binary = env!("CARGO_BIN_EXE_balerx");
    let payload = serde_json::json!({ "command": format!("{binary} hook") });
    fs::write(&hooks, payload.to_string()).expect("hook");
    let output = status(&home, &work, &["--strict"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "installed status failed: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!stdout.contains("Not installed —"));
    assert!(stdout.contains("Cursor hooks: installed"));
}

#[test]
fn missing_hook_binary_exits_nonzero() {
    let home = temp_dir("missing-bin-home");
    let work = temp_dir("missing-bin-work");
    let hooks = home.join(".cursor").join("hooks.json");
    fs::create_dir_all(hooks.parent().expect("parent")).expect("dir");
    fs::write(
        &hooks,
        r#"{"command":"/definitely/missing/balerx hook --event-type pre_tool_use"}"#,
    )
    .expect("hook");
    let output = status(&home, &work, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "missing binary should fail: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("missing")
            || stderr.contains("missing")
            || stderr.contains("not executable"),
        "expected a missing/not-executable message:\n{stdout}\n{stderr}"
    );
}

#[test]
fn doctor_exits_nonzero_when_hook_binary_missing() {
    let home = temp_dir("doctor-missing-home");
    let work = temp_dir("doctor-missing-work");
    let hooks = home.join(".cursor").join("hooks.json");
    fs::create_dir_all(hooks.parent().expect("parent")).expect("dir");
    fs::write(
        &hooks,
        r#"{"command":"/definitely/missing/balerx hook --event-type pre_tool_use"}"#,
    )
    .expect("hook");
    let output = Command::new(env!("CARGO_BIN_EXE_balerx"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .current_dir(&work)
        .arg("doctor")
        .output()
        .expect("doctor");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "doctor should fail: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("missing")
            || stderr.contains("missing")
            || stderr.contains("not executable"),
        "expected a missing/not-executable message:\n{stdout}\n{stderr}"
    );
}
