use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn temp_dir(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "balerx-fail-safe-{label}-{}-{id}-{nanos}",
        std::process::id(),
    ));
    fs::create_dir(&dir).unwrap_or_else(|err| panic!("temp dir {}: {err}", dir.display()));
    dir
}

fn policy_path(dir: &Path) -> PathBuf {
    dir.join("policy.yaml")
}

fn hook(
    policy: &Path,
    data: &Path,
    event: &str,
    payload: &[u8],
    delay: Option<Duration>,
) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_balerx"))
        .args(["hook", "--event-type", event])
        .env("BALERX_POLICY", policy)
        .env("BALERX_DATA_DIR", data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn balerx");
    if let Some(delay) = delay {
        std::thread::sleep(delay);
    }
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload)
        .expect("write payload");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait");
    (
        output.status.code().unwrap_or(1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn doctor(home: &Path, policy: &Path, data: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_balerx"))
        .arg("doctor")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("BALERX_POLICY", policy)
        .env("BALERX_DATA_DIR", data)
        .output()
        .expect("doctor")
}

fn write_policy(path: &Path, body: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("policy dir");
    }
    fs::write(path, body).expect("write policy");
}

#[test]
fn missing_policy_keeps_built_in_default() {
    let dir = temp_dir("missing");
    let data = dir.join("data");
    let missing = dir.join("no-such-policy.yaml");
    let (code, stdout, _stderr) = hook(
        &missing,
        &data,
        "pre_tool_use",
        br#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/.ssh/id_rsa"}}"#,
        None,
    );
    assert_eq!(code, 2, "{stdout}");
    assert!(stdout.contains("\"deny\""), "{stdout}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn empty_and_invalid_policy_fail_closed() {
    let dir = temp_dir("invalid");
    let data = dir.join("data");
    let empty = policy_path(&dir.join("empty"));
    write_policy(&empty, "");
    let payload =
        br#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/project/src/main.rs"}}"#;
    let (code, stdout, stderr) = hook(&empty, &data, "pre_tool_use", payload, None);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("\"ask\""), "{stdout}");
    assert!(!stdout.contains("\"allow\""), "{stdout}");
    assert!(stderr.contains("warning:"), "{stderr}");
    assert!(stderr.contains("empty"), "{stderr}");
    assert!(stderr.contains("Failing closed"), "{stderr}");

    let invalid = policy_path(&dir.join("invalid"));
    write_policy(&invalid, "version: [\n");
    let (code, stdout, stderr) = hook(&invalid, &data, "pre_tool_use", payload, None);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("\"ask\""), "{stdout}");
    assert!(stderr.contains("invalid"), "{stderr}");
    assert!(stderr.contains("Failing closed"), "{stderr}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn oversized_hook_input_returns_ask() {
    let dir = temp_dir("oversize");
    let data = dir.join("data");
    let policy = policy_path(&dir);
    write_policy(
        &policy,
        "version: \"1.0.0\"\nglobal:\n  fail_open: true\n  timeout_ms: 5000\nrules: []\n",
    );
    let mut payload = Vec::with_capacity(1024 * 1024 + 8);
    payload.extend_from_slice(br#"{"tool_name":"Read","pad":""#);
    payload.resize(1024 * 1024 + 1, b'x');
    payload.push(b'"');
    payload.push(b'}');
    let (code, stdout, stderr) = hook(&policy, &data, "pre_tool_use", &payload, None);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("\"ask\""), "{stdout}");
    assert!(!stdout.contains("\"allow\""), "{stdout}");
    assert!(
        stdout.contains("1 MB") || stderr.contains("1 MB"),
        "{stdout}\n{stderr}"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn wall_clock_timeout_honors_fail_open() {
    let dir = temp_dir("timeout");
    let data_closed = dir.join("data-closed");
    let data_open = dir.join("data-open");
    let payload = br#"{"command":"echo ship","cwd":"/work"}"#;
    let closed = policy_path(&dir.join("closed"));
    write_policy(
        &closed,
        "version: \"1.0.0\"\nglobal:\n  fail_open: false\n  timeout_ms: 40\nrules: []\n",
    );
    let started = Instant::now();
    let (code, stdout, stderr) = hook(
        &closed,
        &data_closed,
        "pre_tool_use",
        payload,
        Some(Duration::from_millis(80)),
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "hook hung for {elapsed:?}"
    );
    assert_eq!(code, 2, "{stdout}\n{stderr}");
    assert!(stdout.contains("\"deny\""), "{stdout}");
    assert!(
        stdout.contains("timeout_ms") || stderr.contains("timeout_ms"),
        "{stdout}\n{stderr}"
    );

    let open = policy_path(&dir.join("open"));
    write_policy(
        &open,
        "version: \"1.0.0\"\nglobal:\n  fail_open: true\n  timeout_ms: 40\nrules: []\n",
    );
    let (code, stdout, stderr) = hook(
        &open,
        &data_open,
        "pre_tool_use",
        payload,
        Some(Duration::from_millis(80)),
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("\"allow\""), "{stdout}");
    assert!(stderr.contains("fail_open:"), "{stderr}");
    assert!(stderr.contains("fail_open is true"), "{stderr}");
    let log = fs::read_to_string(data_open.join("logs").join("activity.jsonl")).expect("log");
    assert!(
        log.contains("\"fail_open\":true") || log.contains("\"fail_open\": true"),
        "{log}"
    );
    assert!(log.contains("timeout_ms"), "{log}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn doctor_reports_empty_and_invalid_policy() {
    let dir = temp_dir("doctor");
    let home = dir.join("home");
    fs::create_dir_all(&home).expect("home");
    let data = dir.join("data");
    let missing = dir.join("missing.yaml");
    let ok = doctor(&home, &missing, &data);
    let stdout = String::from_utf8_lossy(&ok.stdout);
    assert!(
        ok.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(stdout.contains("built-in default"), "{stdout}");

    let empty = policy_path(&dir.join("empty"));
    write_policy(&empty, "   \n");
    let empty_out = doctor(&home, &empty, &data);
    let empty_stdout = String::from_utf8_lossy(&empty_out.stdout);
    let empty_stderr = String::from_utf8_lossy(&empty_out.stderr);
    assert_eq!(
        empty_out.status.code(),
        Some(1),
        "{empty_stdout}\n{empty_stderr}"
    );
    assert!(empty_stdout.contains("empty"), "{empty_stdout}");
    assert!(empty_stderr.contains("empty"), "{empty_stderr}");

    let invalid = policy_path(&dir.join("invalid"));
    write_policy(&invalid, "version: [\n");
    let invalid_out = doctor(&home, &invalid, &data);
    let invalid_stdout = String::from_utf8_lossy(&invalid_out.stdout);
    let invalid_stderr = String::from_utf8_lossy(&invalid_out.stderr);
    assert_eq!(
        invalid_out.status.code(),
        Some(1),
        "{invalid_stdout}\n{invalid_stderr}"
    );
    assert!(invalid_stdout.contains("invalid"), "{invalid_stdout}");
    assert!(invalid_stderr.contains("invalid"), "{invalid_stderr}");

    let valid = policy_path(&dir.join("valid"));
    write_policy(
        &valid,
        "version: \"1.0.0\"\nglobal:\n  fail_open: false\n  timeout_ms: 200\nrules: []\n",
    );
    let valid_out = doctor(&home, &valid, &data);
    let valid_stdout = String::from_utf8_lossy(&valid_out.stdout);
    assert!(
        valid_out.status.success(),
        "{valid_stdout}\n{}",
        String::from_utf8_lossy(&valid_out.stderr)
    );
    assert!(valid_stdout.contains("valid"), "{valid_stdout}");
    assert!(valid_stdout.contains("fail_open=false"), "{valid_stdout}");
    assert!(valid_stdout.contains("timeout_ms=200"), "{valid_stdout}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn policy_edit_keeps_fail_open_and_timeout_ms() {
    let home = temp_dir("edit");
    fs::create_dir_all(home.join(".balerx")).expect("balerx dir");
    let path = home.join(".balerx").join("policy.yaml");
    write_policy(
        &path,
        r#"
version: "1.0.0"
global:
  fail_open: false
  timeout_ms: 200
rules:
  - id: deny_env_files
    description: Deny reading .env files
    enabled: true
    action: deny
    conditions:
      - type: path_pattern
        pattern: "**/.env*"
"#,
    );
    let output = Command::new(env!("CARGO_BIN_EXE_balerx"))
        .args(["policy", "edit", "--preset", "balanced"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("BALERX_POLICY")
        .current_dir(&home)
        .output()
        .expect("policy edit");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}\n{stdout}");
    assert!(
        stdout.contains("fail_open is false and timeout_ms is 200."),
        "{stdout}"
    );
    let text = fs::read_to_string(&path).expect("policy");
    let parsed: serde_yaml::Value = serde_yaml::from_str(&text).expect("yaml");
    assert_eq!(parsed["global"]["fail_open"].as_bool(), Some(false));
    assert_eq!(parsed["global"]["timeout_ms"].as_i64(), Some(200));
    assert!(text.contains("guard_rm_rf"), "{text}");
    let _ = fs::remove_dir_all(home);
}

const RULES_ONLY: &str = r#"
version: "1.0.0"
rules:
  - id: deny_env_files
    description: Deny reading .env files
    enabled: true
    action: deny
    conditions:
      - type: path_pattern
        pattern: "**/.env*"
"#;

#[test]
fn omitted_or_empty_global_uses_documented_defaults() {
    let dir = temp_dir("defaults");
    let home = dir.join("home");
    fs::create_dir_all(&home).expect("home");
    let data = dir.join("data");
    let rules_only = policy_path(&dir.join("rules-only"));
    write_policy(&rules_only, RULES_ONLY);
    let deny_payload =
        br#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/project/.env"}}"#;
    let (code, stdout, stderr) = hook(&rules_only, &data, "pre_tool_use", deny_payload, None);
    assert_eq!(code, 2, "{stdout}\n{stderr}");
    assert!(stdout.contains("\"deny\""), "{stdout}");
    assert!(!stderr.contains("timeout_ms"), "{stderr}");
    let allow_payload =
        br#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/project/src/main.rs"}}"#;
    let (code, stdout, stderr) = hook(&rules_only, &data, "pre_tool_use", allow_payload, None);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("\"allow\""), "{stdout}");
    assert!(!stdout.contains("timeout_ms"), "{stdout}");

    let empty_global = policy_path(&dir.join("empty-global"));
    write_policy(&empty_global, "version: \"1.0.0\"\nglobal: {}\nrules: []\n");
    let (code, stdout, stderr) = hook(&empty_global, &data, "pre_tool_use", allow_payload, None);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("\"allow\""), "{stdout}");
    assert!(!stdout.contains("timeout_ms"), "{stdout}");

    let rules_doctor = doctor(&home, &rules_only, &data);
    let rules_stdout = String::from_utf8_lossy(&rules_doctor.stdout);
    assert!(
        rules_doctor.status.success(),
        "{rules_stdout}\n{}",
        String::from_utf8_lossy(&rules_doctor.stderr)
    );
    assert!(rules_stdout.contains("valid"), "{rules_stdout}");
    assert!(rules_stdout.contains("fail_open=true"), "{rules_stdout}");
    assert!(rules_stdout.contains("timeout_ms=50"), "{rules_stdout}");

    let empty_doctor = doctor(&home, &empty_global, &data);
    let empty_stdout = String::from_utf8_lossy(&empty_doctor.stdout);
    assert!(
        empty_doctor.status.success(),
        "{empty_stdout}\n{}",
        String::from_utf8_lossy(&empty_doctor.stderr)
    );
    assert!(empty_stdout.contains("valid"), "{empty_stdout}");
    assert!(empty_stdout.contains("fail_open=true"), "{empty_stdout}");
    assert!(empty_stdout.contains("timeout_ms=50"), "{empty_stdout}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn comment_only_policy_fails_closed() {
    let dir = temp_dir("comments");
    let home = dir.join("home");
    fs::create_dir_all(&home).expect("home");
    let data = dir.join("data");
    let comments = policy_path(&dir.join("comments"));
    write_policy(&comments, "# not a policy\n");
    let payload =
        br#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/project/src/main.rs"}}"#;
    let (code, stdout, stderr) = hook(&comments, &data, "pre_tool_use", payload, None);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("\"ask\""), "{stdout}");
    assert!(!stdout.contains("\"allow\""), "{stdout}");
    assert!(stderr.contains("warning:"), "{stderr}");
    assert!(stderr.contains("empty"), "{stderr}");
    assert!(stderr.contains("Failing closed"), "{stderr}");

    let doctor_out = doctor(&home, &comments, &data);
    let doctor_stdout = String::from_utf8_lossy(&doctor_out.stdout);
    let doctor_stderr = String::from_utf8_lossy(&doctor_out.stderr);
    assert_eq!(
        doctor_out.status.code(),
        Some(1),
        "{doctor_stdout}\n{doctor_stderr}"
    );
    assert!(doctor_stdout.contains("empty"), "{doctor_stdout}");
    assert!(doctor_stderr.contains("empty"), "{doctor_stderr}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn policy_edit_on_rules_only_writes_documented_defaults() {
    let home = temp_dir("edit-rules");
    fs::create_dir_all(home.join(".balerx")).expect("balerx dir");
    let path = home.join(".balerx").join("policy.yaml");
    write_policy(&path, RULES_ONLY);
    let output = Command::new(env!("CARGO_BIN_EXE_balerx"))
        .args(["policy", "edit", "--yes"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("BALERX_POLICY")
        .current_dir(&home)
        .output()
        .expect("policy edit");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}\n{stdout}");
    assert!(
        stdout.contains("fail_open is true and timeout_ms is 50."),
        "{stdout}"
    );
    let text = fs::read_to_string(&path).expect("policy");
    let parsed: serde_yaml::Value = serde_yaml::from_str(&text).expect("yaml");
    assert_eq!(parsed["global"]["fail_open"].as_bool(), Some(true));
    assert_eq!(parsed["global"]["timeout_ms"].as_i64(), Some(50));
    let _ = fs::remove_dir_all(home);
}
