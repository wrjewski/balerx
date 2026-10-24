use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn temp_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "balerx-uninstall-{label}-{}-{id}-{nanos}",
        std::process::id(),
    ));
    fs::create_dir(&dir).unwrap_or_else(|err| panic!("temp dir {}: {err}", dir.display()));
    dir
}

fn write_hooks(home: &Path, work: &Path) {
    let claude = home.join(".claude").join("settings.json");
    fs::create_dir_all(claude.parent().expect("parent")).expect("claude dir");
    fs::write(
        &claude,
        r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"balerx hook --event-type pre_tool_use"},{"type":"command","command":"echo keep-me"}]}]}}"#,
    )
    .expect("claude settings");

    let project = work.join(".claude").join("settings.json");
    fs::create_dir_all(project.parent().expect("parent")).expect("project dir");
    fs::write(
        &project,
        r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"balerx hook --event-type pre_tool_use"}]}]}}"#,
    )
    .expect("project settings");

    let cursor = home.join(".cursor").join("hooks.json");
    fs::create_dir_all(cursor.parent().expect("parent")).expect("cursor dir");
    fs::write(
        &cursor,
        r#"{"version":1,"hooks":{"beforeShellExecution":[{"command":"balerx hook --event-type before_shell_execution"},{"command":"echo keep-cursor"}]}}"#,
    )
    .expect("cursor hooks");
}

fn write_state(home: &Path, data: &Path) {
    let policy = home.join(".balerx").join("policy.yaml");
    fs::create_dir_all(policy.parent().expect("parent")).expect("policy dir");
    fs::write(&policy, "version: 1\n").expect("policy");
    let log = data.join("logs").join("activity.jsonl");
    fs::create_dir_all(log.parent().expect("parent")).expect("log dir");
    fs::write(&log, "{}\n").expect("log");
}

fn run(home: &Path, work: &Path, data: &Path, bin: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_DATA_HOME", data.join("unused-xdg"))
        .env("LOCALAPPDATA", data.join("unused-local"))
        .env("BALERX_DATA_DIR", data)
        .env_remove("BALERX_POLICY")
        .current_dir(work)
        .args(args)
        .output()
        .expect("run balerx")
}

fn text(output: &std::process::Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn without_yes_on_a_pipe_removes_nothing() {
    let home = temp_dir("home");
    let work = temp_dir("work");
    let data = temp_dir("data");
    write_hooks(&home, &work);
    write_state(&home, &data);
    let output = run(
        &home,
        &work,
        &data,
        Path::new(env!("CARGO_BIN_EXE_balerx")),
        &["uninstall"],
    );
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("Will remove:"));
    assert!(stdout.contains("Balerx hook commands in"));
    assert!(stdout.contains("Will keep:"));
    assert!(stdout.contains(&home.join(".balerx").display().to_string()));
    assert!(stdout.contains(&data.display().to_string()));
    assert!(stdout.contains("Policy and logs stay. Pass --purge to delete them."));
    assert!(stdout.contains("No terminal attached. Nothing was removed."));
    assert!(stdout.contains("Run: balerx uninstall --yes"));
    assert!(stdout.contains("Run: balerx uninstall --purge --yes"));
    let claude = fs::read_to_string(home.join(".claude").join("settings.json")).expect("read");
    assert!(claude.contains("balerx hook"));
    assert!(home.join(".balerx").join("policy.yaml").is_file());
    assert!(data.join("logs").join("activity.jsonl").is_file());

    let purge = run(
        &home,
        &work,
        &data,
        Path::new(env!("CARGO_BIN_EXE_balerx")),
        &["uninstall", "--purge"],
    );
    let (purge_out, purge_err) = text(&purge);
    assert!(purge.status.success(), "{purge_out}\n{purge_err}");
    assert!(purge_out.contains("No terminal attached. Nothing was removed."));
    assert!(home.join(".balerx").join("policy.yaml").is_file());
    assert!(data.join("logs").join("activity.jsonl").is_file());
}

#[test]
fn yes_removes_only_balerx_hooks_and_keeps_policy_and_logs() {
    let home = temp_dir("home");
    let work = temp_dir("work");
    let data = temp_dir("data");
    write_hooks(&home, &work);
    write_state(&home, &data);
    let other = home.join(".local").join("bin").join("balerx");
    fs::create_dir_all(other.parent().expect("parent")).expect("bin dir");
    fs::write(&other, "not-the-running-binary").expect("other binary");
    let output = run(
        &home,
        &work,
        &data,
        Path::new(env!("CARGO_BIN_EXE_balerx")),
        &["uninstall", "--yes"],
    );
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("Removed Balerx hook commands from"));
    assert!(stdout.contains("Will keep:"));
    assert!(stdout.contains("Policy and logs stay. Pass --purge to delete them."));
    assert!(other.is_file());
    if cfg!(windows) {
        assert!(stdout.contains(r#"Remove-Item -Recurse -Force "$env:LOCALAPPDATA\balerx""#));
    } else {
        assert!(stdout.contains("Left"));
        assert!(stdout.contains("It is not the running binary"));
    }

    let claude = fs::read_to_string(home.join(".claude").join("settings.json")).expect("claude");
    assert!(!claude.contains("balerx hook"));
    assert!(claude.contains("echo keep-me"));
    let project = fs::read_to_string(work.join(".claude").join("settings.json")).expect("project");
    assert!(!project.contains("balerx"));
    let cursor = fs::read_to_string(home.join(".cursor").join("hooks.json")).expect("cursor");
    assert!(!cursor.contains("balerx"));
    assert!(cursor.contains("echo keep-cursor"));
    assert!(home.join(".balerx").join("policy.yaml").is_file());
    assert!(data.join("logs").join("activity.jsonl").is_file());
}

#[test]
fn purge_yes_deletes_known_files_and_keeps_unrelated_ones() {
    let home = temp_dir("home");
    let work = temp_dir("work");
    let data = temp_dir("documents");
    write_hooks(&home, &work);
    write_state(&home, &data);
    fs::write(home.join(".balerx").join("policy.yaml.bak"), "old\n").expect("bak");
    fs::write(home.join(".balerx").join("notes.txt"), "keep\n").expect("notes");
    fs::create_dir_all(data.join("photos")).expect("photos");
    fs::write(data.join("photos").join("pic.txt"), "pic\n").expect("pic");
    fs::write(data.join("canaries.json"), "{}\n").expect("registry");
    let output = run(
        &home,
        &work,
        &data,
        Path::new(env!("CARGO_BIN_EXE_balerx")),
        &["uninstall", "--purge", "--yes"],
    );
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    let policy = home.join(".balerx").join("policy.yaml");
    let backup = home.join(".balerx").join("policy.yaml.bak");
    let log = data.join("logs").join("activity.jsonl");
    let registry = data.join("canaries.json");
    assert!(stdout.contains(&format!("  {}", policy.display())));
    assert!(stdout.contains(&format!("  {}", backup.display())));
    assert!(stdout.contains(&format!("  {}", log.display())));
    assert!(stdout.contains(&format!("  {}", registry.display())));
    assert!(stdout.contains(&format!("  {}", data.join("logs").display())));
    assert!(stdout.contains("Unknown files stay."));
    assert!(stdout.contains(&home.join(".balerx").join("notes.txt").display().to_string()));
    assert!(stdout.contains(&data.join("photos").display().to_string()));
    assert!(!stdout.contains("Policy and logs stay"));
    assert!(!policy.exists());
    assert!(!backup.exists());
    assert!(!log.exists());
    assert!(!registry.exists());
    assert!(!data.join("logs").exists());
    assert!(data.join("photos").join("pic.txt").is_file());
    assert!(home.join(".balerx").join("notes.txt").is_file());
    assert!(home.join(".balerx").is_dir());
    assert!(data.is_dir());
    let claude = fs::read_to_string(home.join(".claude").join("settings.json")).expect("claude");
    assert!(claude.contains("echo keep-me"));
    assert!(!claude.contains("balerx hook"));
    assert!(!claude.contains("\"PostToolUse\": []") && !claude.contains("\"PostToolUse\":[]"));
}

#[test]
fn purge_removes_an_empty_default_config_dir_only() {
    let home = temp_dir("home");
    let work = temp_dir("work");
    let local = home.join("AppData").join("Local");
    let data = if cfg!(windows) {
        local.join("balerx")
    } else if cfg!(target_os = "macos") {
        home.join("Library")
            .join("Application Support")
            .join("balerx")
    } else {
        home.join(".local").join("share").join("balerx")
    };
    write_state(&home, &data);
    let output = Command::new(env!("CARGO_BIN_EXE_balerx"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("LOCALAPPDATA", &local)
        .env_remove("BALERX_DATA_DIR")
        .env_remove("XDG_DATA_HOME")
        .env_remove("BALERX_POLICY")
        .current_dir(&work)
        .args(["uninstall", "--purge", "--yes"])
        .output()
        .expect("run");
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(!home.join(".balerx").exists(), "{stdout}");
    assert!(
        !data.join("logs").join("activity.jsonl").exists(),
        "{stdout}"
    );
    if cfg!(windows) {
        assert!(data.is_dir(), "{stdout}");
        assert!(stdout.contains(r#"Remove-Item -Recurse -Force "$env:LOCALAPPDATA\balerx""#));
    } else {
        assert!(!data.exists(), "{stdout}");
    }
    assert!(stdout.contains(&format!("Removed {}", home.join(".balerx").display())));
}

#[test]
fn relative_home_and_data_dir_refuse_purge() {
    let work = temp_dir("work");
    fs::create_dir_all(work.join(".balerx")).expect("config");
    fs::write(work.join(".balerx").join("policy.yaml"), "version: 1\n").expect("policy");
    fs::create_dir_all(work.join("balerx")).expect("data");
    fs::write(work.join("balerx").join("notes.txt"), "keep\n").expect("notes");
    let output = Command::new(env!("CARGO_BIN_EXE_balerx"))
        .env("HOME", ".")
        .env("USERPROFILE", ".")
        .env("BALERX_DATA_DIR", "balerx")
        .env_remove("XDG_DATA_HOME")
        .env_remove("BALERX_POLICY")
        .current_dir(&work)
        .args(["uninstall", "--purge", "--yes"])
        .output()
        .expect("run");
    let (stdout, stderr) = text(&output);
    assert!(!output.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("Home directory is not an absolute path")
            || stderr.contains("Home directory is not an absolute path"),
        "{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("The data directory is not an absolute path")
            || stderr.contains("The data directory is not an absolute path"),
        "{stdout}\n{stderr}"
    );
    assert!(work.join(".balerx").join("policy.yaml").is_file());
    assert!(work.join("balerx").join("notes.txt").is_file());
}

#[cfg(unix)]
#[test]
fn symlink_logs_are_not_followed() {
    let home = temp_dir("home");
    let work = temp_dir("work");
    let data = temp_dir("data");
    let outside = temp_dir("outside");
    write_state(&home, &data);
    fs::remove_dir_all(data.join("logs")).expect("remove logs");
    fs::write(outside.join("secret.txt"), "secret\n").expect("secret");
    std::os::unix::fs::symlink(&outside, data.join("logs")).expect("symlink");
    let output = run(
        &home,
        &work,
        &data,
        Path::new(env!("CARGO_BIN_EXE_balerx")),
        &["uninstall", "--purge", "--yes"],
    );
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(outside.join("secret.txt").is_file(), "{stdout}");
    assert!(data.join("logs").is_symlink());
    assert!(stdout.contains("It is a symlink."));
    assert!(stdout.contains("Unknown files stay."));
}

#[test]
fn webhook_script_stays_and_empty_hook_keys_are_removed() {
    let home = temp_dir("home");
    let work = temp_dir("work");
    let data = temp_dir("data");
    let settings = home.join(".claude").join("settings.json");
    fs::create_dir_all(settings.parent().expect("parent")).expect("dir");
    fs::write(
        &settings,
        r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"balerx hook --event-type pre_tool_use"},{"type":"command","command":"my-balerx-webhook.sh"}]}],"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"balerx hook --event-type post_tool_use"}]}]}}"#,
    )
    .expect("settings");
    let output = run(
        &home,
        &work,
        &data,
        Path::new(env!("CARGO_BIN_EXE_balerx")),
        &["uninstall", "--yes"],
    );
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    let text = fs::read_to_string(&settings).expect("read");
    assert!(text.contains("my-balerx-webhook.sh"));
    assert!(!text.contains("balerx hook"));
    assert!(!text.contains("PostToolUse"));
}

#[test]
fn running_install_path_is_removed_on_unix_and_printed_on_windows() {
    let home = temp_dir("home");
    let work = temp_dir("work");
    let data = temp_dir("data");
    let dest = home.join(".local").join("bin").join("balerx");
    fs::create_dir_all(dest.parent().expect("parent")).expect("bin dir");
    fs::copy(env!("CARGO_BIN_EXE_balerx"), &dest).expect("copy binary");
    #[cfg(unix)]
    let bin = {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&dest).expect("meta").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&dest, permissions).expect("chmod");
        dest.clone()
    };
    #[cfg(windows)]
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_balerx"));
    let output = run(&home, &work, &data, &bin, &["uninstall", "--yes"]);
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    if cfg!(windows) {
        assert!(dest.is_file(), "windows must not delete the running binary");
        assert!(stdout.contains(r#"Remove-Item -Recurse -Force "$env:LOCALAPPDATA\balerx""#));
        assert!(stdout.contains("SetEnvironmentVariable('Path', $kept, 'User')"));
        assert!(stdout.contains("$env:Path"));
    } else {
        assert!(
            !dest.exists(),
            "unix install path should be removed\n{stdout}"
        );
        assert!(stdout.contains(&format!("Removed {}", dest.display())));
        assert!(!stdout.contains("Remove-Item"));
    }
}
