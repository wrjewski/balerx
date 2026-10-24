use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "balerx-setup-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn run(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_balerx"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("BALERX_POLICY")
        .current_dir(home)
        .output()
        .expect("run balerx")
}

fn policy_file(home: &Path) -> PathBuf {
    home.join(".balerx").join("policy.yaml")
}

#[test]
fn non_tty_setup_writes_balanced_without_prompting() {
    let home = temp_dir("tty");
    let output = run(&home, &["setup"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "setup hung or failed: {stderr}\n{stdout}"
    );
    assert!(stdout.contains("No terminal attached. Wrote the balanced policy."));
    let text = fs::read_to_string(policy_file(&home)).expect("policy");
    let policy: serde_yaml::Value = serde_yaml::from_str(&text).expect("yaml");
    assert_eq!(policy["global"]["fail_open"].as_bool(), Some(true));
    assert_eq!(policy["global"]["timeout_ms"].as_i64(), Some(50));
    let rules = policy["rules"].as_sequence().expect("rules");
    assert!(rules
        .iter()
        .all(|rule| rule["enabled"].as_bool() == Some(true)));
    assert_eq!(
        rule(&policy, "deny_env_files")["action"].as_str(),
        Some("deny")
    );
    assert_eq!(rule(&policy, "guard_rm_rf")["action"].as_str(), Some("ask"));
    assert_eq!(
        rule(&policy, "guard_download_pipe")["action"].as_str(),
        Some("ask")
    );
    assert_eq!(
        rule(&policy, "guard_package_install")["action"].as_str(),
        Some("ask")
    );
    assert_eq!(
        rule(&policy, "guard_mcp_server")["action"].as_str(),
        Some("ask")
    );
    assert!(text.contains("**/.aws/credentials"));
    let _ = fs::remove_dir_all(home);
}

#[test]
fn presets_write_distinct_yaml_and_policy_init_matches_setup() {
    let home = temp_dir("presets");
    for (preset, secret_on, shell_action) in [
        ("minimal", true, "ask"),
        ("balanced", true, "ask"),
        ("strict", true, "deny"),
    ] {
        let output = run(&home, &["setup", "--preset", preset, "--replace"]);
        assert!(
            output.status.success(),
            "{preset}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = fs::read_to_string(policy_file(&home)).expect("policy");
        let policy: serde_yaml::Value = serde_yaml::from_str(&text).expect("yaml");
        assert_eq!(
            rule(&policy, "deny_ssh_keys")["enabled"].as_bool(),
            Some(secret_on)
        );
        assert_eq!(
            rule(&policy, "guard_force_push")["action"].as_str(),
            Some(shell_action)
        );
        let shell_on = preset != "minimal";
        assert_eq!(
            rule(&policy, "guard_force_push")["enabled"].as_bool(),
            Some(shell_on)
        );
        assert_eq!(
            rule(&policy, "guard_mcp_server")["enabled"].as_bool(),
            Some(shell_on)
        );
    }
    fs::remove_file(policy_file(&home)).expect("remove");
    let output = run(&home, &["policy", "init", "--preset", "minimal"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = fs::read_to_string(policy_file(&home)).expect("policy");
    let policy: serde_yaml::Value = serde_yaml::from_str(&text).expect("yaml");
    assert_eq!(
        rule(&policy, "guard_package_install")["enabled"].as_bool(),
        Some(false)
    );
    let _ = fs::remove_dir_all(home);
}

#[test]
fn existing_policy_is_kept_until_replace_copies_a_backup() {
    let home = temp_dir("backup");
    fs::create_dir_all(home.join(".balerx")).expect("dir");
    let path = policy_file(&home);
    fs::write(&path, "version: \"1.0.0\"\nrules: []\n").expect("seed");
    let refused = run(&home, &["setup", "--yes"]);
    assert_eq!(refused.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("A policy already exists"));
    assert!(stderr.contains("--replace is required"));
    assert!(stderr.contains("--yes and --preset do not replace it"));
    let preset_refused = run(&home, &["setup", "--preset", "minimal"]);
    assert_eq!(preset_refused.status.code(), Some(1));
    let preset_err = String::from_utf8_lossy(&preset_refused.stderr);
    assert!(preset_err.contains("--replace is required"));
    assert_eq!(
        fs::read_to_string(&path).expect("unchanged"),
        "version: \"1.0.0\"\nrules: []\n"
    );
    assert!(!path.with_file_name("policy.yaml.bak").exists());

    let replaced = run(&home, &["setup", "--yes", "--replace"]);
    assert!(
        replaced.status.success(),
        "{}",
        String::from_utf8_lossy(&replaced.stderr)
    );
    let stdout = String::from_utf8_lossy(&replaced.stdout);
    assert!(stdout.contains("policy.yaml.bak"));
    assert_eq!(
        fs::read_to_string(path.with_file_name("policy.yaml.bak")).expect("bak"),
        "version: \"1.0.0\"\nrules: []\n"
    );
    let again = run(&home, &["policy", "edit", "--preset", "strict"]);
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert!(path.with_file_name("policy.yaml.bak.1").is_file());
    let shown = run(&home, &["policy", "show"]);
    let show_out = String::from_utf8_lossy(&shown.stdout);
    assert!(shown.status.success(), "{show_out}");
    assert!(show_out.contains("[deny] on guard_rm_rf"));
    assert!(show_out.contains("deny_aws_credentials"));
    let _ = fs::remove_dir_all(home);
}

#[test]
fn setup_does_not_install_hooks_and_scan_mentions_a_missing_policy() {
    let home = temp_dir("hint");
    let work = temp_dir("work");
    fs::create_dir_all(home.join(".claude")).expect("claude");
    fs::write(home.join(".claude/settings.json"), "{\"theme\":\"dark\"}\n").expect("settings");
    let setup = Command::new(env!("CARGO_BIN_EXE_balerx"))
        .args(["setup", "--yes"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("BALERX_POLICY")
        .current_dir(&work)
        .output()
        .expect("setup");
    let stdout = String::from_utf8_lossy(&setup.stdout);
    assert!(setup.status.success(), "{stdout}");
    assert!(stdout.contains("Run: balerx guard install claude-code"));
    assert!(!stdout.contains("api.github.com"));
    let settings = fs::read_to_string(home.join(".claude/settings.json")).expect("settings");
    assert_eq!(settings, "{\"theme\":\"dark\"}\n");

    fs::remove_file(policy_file(&home)).expect("remove policy");
    let scan = Command::new(env!("CARGO_BIN_EXE_balerx"))
        .args(["scan", "--format", "text"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("BALERX_POLICY")
        .current_dir(&work)
        .output()
        .expect("scan");
    let stderr = String::from_utf8_lossy(&scan.stderr);
    assert!(stderr.contains("No policy set yet. Run: balerx setup"));
    let quiet = Command::new(env!("CARGO_BIN_EXE_balerx"))
        .args(["scan", "--quiet"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("BALERX_POLICY")
        .current_dir(&work)
        .output()
        .expect("quiet scan");
    assert!(!String::from_utf8_lossy(&quiet.stderr).contains("No policy set yet"));

    let install = Command::new(env!("CARGO_BIN_EXE_balerx"))
        .args(["guard", "install", "cursor"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("BALERX_POLICY")
        .current_dir(&work)
        .output()
        .expect("install");
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );
    assert!(
        String::from_utf8_lossy(&install.stderr).contains("No policy set yet. Run: balerx setup")
    );
    let _ = fs::remove_dir_all(home);
    let _ = fs::remove_dir_all(work);
}

fn rule<'a>(policy: &'a serde_yaml::Value, id: &str) -> &'a serde_yaml::Value {
    policy["rules"]
        .as_sequence()
        .expect("rules")
        .iter()
        .find(|rule| rule["id"] == id)
        .unwrap_or_else(|| panic!("missing {id}"))
}
