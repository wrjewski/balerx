use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "balerx-banner-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn balerx(home: &std::path::Path, args: &[&str], columns: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_balerx"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("COLUMNS", columns)
        .env_remove("NO_COLOR")
        .env_remove("BALERX_POLICY")
        .current_dir(home)
        .output()
        .expect("run balerx")
}

fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn setup_and_policy_init_print_the_banner_and_scans_do_not() {
    let home = temp_dir("setup");
    let setup = balerx(&home, &["setup"], "100");
    let setup_out = stdout_of(&setup);
    assert!(setup.status.success(), "{setup_out}");
    assert!(setup_out.contains("Security for AI agents"), "{setup_out}");
    assert!(setup_out.contains("v0.1.6"), "{setup_out}");
    assert!(setup_out.contains("Balerx Gate"), "{setup_out}");
    assert!(!setup_out.contains('\u{1b}'), "{setup_out}");
    assert!(setup_out.contains("No terminal attached. Wrote the balanced policy."));

    fs::remove_file(home.join(".balerx").join("policy.yaml")).expect("remove policy");
    let init = balerx(&home, &["policy", "init", "--yes"], "100");
    let init_out = stdout_of(&init);
    assert!(init.status.success(), "{init_out}");
    assert!(init_out.contains("Security for AI agents"), "{init_out}");
    assert!(!init_out.contains('\u{1b}'), "{init_out}");

    let edit = balerx(&home, &["policy", "edit", "--preset", "minimal"], "100");
    let edit_out = stdout_of(&edit);
    assert!(edit.status.success(), "{edit_out}");
    assert!(
        !edit_out.contains("Security for AI agents"),
        "policy edit printed the banner: {edit_out}"
    );

    let narrow = balerx(&home, &["setup", "--yes", "--replace"], "60");
    let narrow_out = stdout_of(&narrow);
    assert!(narrow.status.success(), "{narrow_out}");
    assert_eq!(
        narrow_out.lines().next(),
        Some(">< Balerx Gate  v0.1.6"),
        "{narrow_out}"
    );
    assert!(
        !narrow_out.contains("Security for AI agents"),
        "{narrow_out}"
    );
    assert!(!narrow_out.contains('\u{1b}'), "{narrow_out}");

    let plain = Command::new(env!("CARGO_BIN_EXE_balerx"))
        .args(["setup", "--yes", "--replace", "--no-color"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("COLUMNS", "100")
        .env("NO_COLOR", "1")
        .env_remove("BALERX_POLICY")
        .current_dir(&home)
        .output()
        .expect("no-color setup");
    let plain_out = stdout_of(&plain);
    assert!(plain.status.success(), "{plain_out}");
    assert!(plain_out.contains("Security for AI agents"), "{plain_out}");
    assert!(!plain_out.contains('\u{1b}'), "{plain_out}");

    let json = balerx(&home, &["scan", "--format", "json"], "100");
    let json_out = stdout_of(&json);
    assert!(!json_out.contains("Security for AI agents"), "{json_out}");
    assert!(!json_out.contains('\u{1b}'), "{json_out}");
    assert!(json_out.contains("\"findings\""), "{json_out}");

    let json_path = home.join("scan.json");
    let file_json = balerx(
        &home,
        &["scan", "--json", json_path.to_str().expect("utf8")],
        "100",
    );
    let file_out = stdout_of(&file_json);
    assert!(!file_out.contains("Security for AI agents"), "{file_out}");
    assert!(!file_out.contains('\u{1b}'), "{file_out}");

    let mut hook = Command::new(env!("CARGO_BIN_EXE_balerx"))
        .args(["hook", "--event-type", "pre_tool_use"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("COLUMNS", "100")
        .env("BALERX_POLICY", "/tmp/balerx-missing-banner-policy.yaml")
        .env("BALERX_DATA_DIR", home.join("data"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hook");
    hook.stdin
        .as_mut()
        .expect("stdin")
        .write_all(br#"{"tool_name":"Read","tool_input":{"file_path":"/tmp/readme.md"}}"#)
        .expect("payload");
    let hook_output = hook.wait_with_output().expect("hook");
    let hook_out = stdout_of(&hook_output);
    assert!(!hook_out.contains("Security for AI agents"), "{hook_out}");
    assert!(!hook_out.contains('\u{1b}'), "{hook_out}");

    for args in [
        ["--help"].as_slice(),
        ["--version"].as_slice(),
        ["version"].as_slice(),
    ] {
        let output = balerx(&home, args, "100");
        let text = stdout_of(&output);
        assert!(output.status.success(), "{args:?} {text}");
        assert!(!text.contains("Security for AI agents"), "{args:?} {text}");
        assert!(!text.contains('\u{1b}'), "{args:?} {text}");
    }

    let _ = fs::remove_dir_all(home);
}
