use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "balerx-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn command(home: &PathBuf, work: &PathBuf) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_balerx"));
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .current_dir(work);
    command
}

#[test]
fn hook_gap_reports_name_the_install_command_in_every_format() {
    let home = temp_dir("home");
    let work = temp_dir("work");
    fs::create_dir_all(home.join(".claude")).expect("claude dir");
    fs::write(home.join(".claude/settings.json"), "{}\n").expect("claude settings");
    fs::create_dir_all(home.join(".cursor")).expect("cursor dir");
    fs::write(home.join(".cursor/mcp.json"), "{}\n").expect("cursor config");

    let json = work.join("scan.json");
    let sarif = work.join("scan.sarif");
    let html = work.join("scan.html");
    let output = command(&home, &work)
        .args([
            "scan",
            "--quiet",
            "--json",
            json.to_str().expect("json path"),
            "--sarif",
            sarif.to_str().expect("sarif path"),
            "--html",
            html.to_str().expect("html path"),
            "--format",
            "text",
        ])
        .output()
        .expect("run scan");
    assert!(
        output.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text = String::from_utf8_lossy(&output.stdout);
    let json_text = fs::read_to_string(&json).expect("read json");
    let sarif_text = fs::read_to_string(&sarif).expect("read sarif");
    let html_text = fs::read_to_string(&html).expect("read html");
    for report in [&text.to_string(), &json_text, &sarif_text, &html_text] {
        assert!(report.contains("Run: balerx guard install claude-code"));
        assert!(report.contains("Run: balerx guard install cursor"));
        assert!(report.contains("More: https://balerxgate.com/docs/guard"));
        assert!(!report.contains("for this agent"));
    }
    let parsed: serde_json::Value = serde_json::from_str(&json_text).expect("json");
    let fixes: Vec<&str> = parsed["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter(|finding| finding["rule_id"] == "HookGapNoGuard")
        .map(|finding| finding["suggested_fix"].as_str().unwrap_or(""))
        .collect();
    assert!(fixes.contains(
        &"Run: balerx guard install claude-code\nMore: https://balerxgate.com/docs/guard"
    ));
    assert!(fixes
        .contains(&"Run: balerx guard install cursor\nMore: https://balerxgate.com/docs/guard"));
    assert!(text.contains("│     Run: balerx guard install claude-code"));
    assert!(text.contains("│     More: https://balerxgate.com/docs/guard"));
}

#[test]
fn installed_hook_clears_hook_gap() {
    let home = temp_dir("hook-home");
    let work = temp_dir("hook-work");
    fs::create_dir_all(home.join(".claude")).expect("claude dir");
    fs::write(
        home.join(".claude/settings.json"),
        "{\"hooks\":{\"PreToolUse\":[{\"command\":\"balerx hook\"}]}}\n",
    )
    .expect("claude settings");
    let output = command(&home, &work)
        .args(["scan", "--quiet", "--format", "json"])
        .output()
        .expect("run scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "scan failed: {}\n{stdout}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!stdout.contains("HOOK-GAP-001"));
    assert!(!stdout.contains("for this agent"));
}

#[test]
fn guard_install_help_keeps_the_documented_agent_values() {
    let output = Command::new(env!("CARGO_BIN_EXE_balerx"))
        .args(["guard", "install", "--help"])
        .output()
        .expect("help");
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{help}");
    assert!(help.contains("[possible values: claude-code, cursor]"));
    assert!(!help.contains("claude_code"));
}

#[test]
fn unknown_agent_lists_the_documented_values() {
    for args in [
        vec!["guard", "install", "claude"],
        vec!["guard", "install", "Claude", "Code"],
        vec!["guard", "install", "Claude Code"],
        vec!["guard", "uninstall", "claude"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_balerx"))
            .args(&args)
            .output()
            .expect("run");
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "{} should fail: {err}",
            args.join(" ")
        );
        assert!(
            err.contains("possible values")
                && err.contains("claude-code")
                && err.contains("cursor"),
            "{} did not list the agent values:\n{err}",
            args.join(" ")
        );
        assert!(
            !err.contains("claude_code"),
            "hidden alias leaked into the error:\n{err}"
        );
    }
}

#[test]
fn guard_install_accepts_case_and_underscore() {
    for agent in ["Claude-Code", "claude_code", "CURSOR"] {
        let home = temp_dir("install-home");
        let work = temp_dir("install-work");
        let output = command(&home, &work)
            .args(["guard", "install", agent])
            .output()
            .expect("install");
        assert!(
            output.status.success(),
            "{agent} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if agent.eq_ignore_ascii_case("cursor") {
            let hooks = fs::read_to_string(home.join(".cursor/hooks.json")).expect("cursor hooks");
            assert!(hooks.contains("balerx"), "{hooks}");
        } else {
            let settings =
                fs::read_to_string(home.join(".claude/settings.json")).expect("claude settings");
            assert!(settings.contains("balerx"), "{settings}");
        }
    }
}
