use std::process::Command;

fn run(args: &[&str], no_color_env: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_balerx"));
    command.args(args);
    if no_color_env {
        command.env("NO_COLOR", "1");
    }
    command.output().expect("run balerx")
}

fn stdout(args: &[&str]) -> String {
    let output = run(args, false);
    assert!(
        output.status.success(),
        "balerx {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n")
}

#[test]
fn version_flags_stay_offline_and_plain() {
    let version = stdout(&["version"]);
    assert_eq!(version, stdout(&["--version"]));
    assert_eq!(version, stdout(&["-V"]));
    assert!(version.starts_with("balerx "));
    assert!(!version.contains("api.github.com"));
    assert!(!version.contains('\u{1b}'));

    let no_color = stdout(&["version", "--no-color"]);
    let from_env = run(&["version"], true);
    assert!(from_env.status.success());
    let from_env = String::from_utf8_lossy(&from_env.stdout).replace("\r\n", "\n");
    assert_eq!(no_color, version);
    assert_eq!(from_env, version);

    let json = stdout(&["version", "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(json.trim()).expect("version json");
    assert!(parsed["current"].as_str().is_some());
    assert!(parsed.get("latest").is_none());
    assert!(!json.contains("api.github.com"));
}

#[test]
fn self_update_without_check_prints_the_install_command() {
    let text = stdout(&["self-update"]);
    assert!(text.contains("This command does not download or replace the binary."));
    assert!(text.contains(if cfg!(windows) {
        r#"Invoke-WebRequest "https://raw.githubusercontent.com/wrjewski/balerx/main/install.ps1" -OutFile install.ps1; powershell -ExecutionPolicy Bypass -File .\install.ps1"#
    } else {
        "curl -fsSL https://raw.githubusercontent.com/wrjewski/balerx/main/install.sh -o install.sh && sh install.sh"
    }));
    assert!(!text.contains("api.github.com"));
    assert!(!text.contains("new version"));
    assert_eq!(text, stdout(&["self-update", "--no-color"]));

    let rejected = run(&["self-update", "--json"], false);
    assert_eq!(rejected.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(stderr.contains("--check"));
    assert_eq!(rejected.stdout, b"");
}

fn collapsed(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn help_lists_the_opt_in_check_and_common_commands() {
    let root_raw = stdout(&["--help"]);
    assert!(!root_raw.contains('\u{1b}'));
    let root = collapsed(&root_raw);
    assert!(root.contains("version"));
    assert!(root.contains("self-update"));
    assert!(root.contains("--check"));
    assert!(root.contains("Print this version"));
    assert!(root.contains("Print the install command for this OS"));
    assert!(!root.contains(
        "Check GitHub for a newer release with --check. Opt-in: nothing is checked unless you ask"
    ));
    assert!(root.contains("Common commands"));
    for example in [
        "balerx scan",
        "balerx setup",
        "balerx guard install claude-code",
        "balerx guard install cursor",
        "balerx guard status",
        "balerx uninstall",
        "balerx doctor",
        "balerx self-update --check",
        "https://balerxgate.com/docs/cli",
    ] {
        assert!(root.contains(example), "missing {example}\n{root_raw}");
    }

    for args in [["version", "--help"], ["self-update", "--help"]] {
        let raw = stdout(&args);
        assert!(!raw.contains('\u{1b}'));
        let help = collapsed(&raw);
        assert!(help.contains("--check"), "missing --check in {args:?}");
        assert!(
            help.contains("single request to the public GitHub releases API"),
            "missing request sentence in {args:?}\n{raw}"
        );
        assert!(
            help.contains("Every other command stays offline except `upload` and `policy pull`."),
            "missing offline sentence in {args:?}\n{raw}"
        );
        assert!(
            help.contains("Opt-in: nothing is checked unless you ask"),
            "missing opt-in sentence in {args:?}\n{raw}"
        );
    }

    let self_update_help = collapsed(&stdout(&["self-update", "--help"]));
    assert!(self_update_help.contains("Windows prints the PowerShell installer"));
    assert!(self_update_help.contains("-ExecutionPolicy Bypass"));
    assert!(self_update_help.contains("macOS and Linux print curl and sh"));

    let doctor = run(&["doctor"], false);
    let doctor_out = String::from_utf8_lossy(&doctor.stdout);
    assert!(doctor_out.contains("offline: doctor does not contact the network"));
}
