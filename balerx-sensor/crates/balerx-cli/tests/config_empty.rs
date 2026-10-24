use std::fs;
use std::path::PathBuf;
use std::process::Command;

const VSCODE_FIX: &str = "Delete the file or add valid contents, for example { \"servers\": {} } for VS Code mcp.json. Nothing was scanned from this file.";
const OTHER_FIX: &str = "Delete the file or add valid contents, for example { \"mcpServers\": {} } for Cursor, Claude, Windsurf, Cline, Roo, Gemini, or another JSON MCP config. Nothing was scanned from this file.";
const CODEX_FIX: &str = "Delete the file or add a [mcp_servers.<name>] entry. An empty table is [mcp_servers]. Nothing was scanned from this file.";

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "balerx-config-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn scan(file: &PathBuf, fail_on: Option<&str>) -> std::process::Output {
    let home = temp_dir("home");
    let work = temp_dir("work");
    let mut command = Command::new(env!("CARGO_BIN_EXE_balerx"));
    command
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .current_dir(&work)
        .arg("scan")
        .arg(file)
        .args(["--quiet", "--format", "json"]);
    if let Some(level) = fail_on {
        command.args(["--fail-on", level]);
    }
    command.output().expect("scan")
}

fn finding(output: &std::process::Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|_| {
        panic!(
            "json: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    parsed["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .find(|finding| finding["rule_id"] == "ConfigInvalid")
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

#[test]
fn empty_vscode_mcp_json_is_info_and_does_not_fail_high() {
    let dir = temp_dir("vscode");
    let file = dir.join(".vscode").join("mcp.json");
    fs::create_dir_all(file.parent().expect("parent")).expect("dir");
    fs::write(&file, b"").expect("empty file");
    let output = scan(&file, Some("high"));
    assert!(
        output.status.success(),
        "empty file failed --fail-on high: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let found = finding(&output);
    assert_eq!(found["severity"], "info");
    assert_eq!(found["title"], "Configuration file is empty");
    assert_eq!(found["suggested_fix"], VSCODE_FIX);
    assert_eq!(found["rule_id"], "ConfigInvalid");

    let low = scan(&file, Some("low"));
    assert!(low.status.success(), "info should not trip --fail-on low");
    let info = scan(&file, Some("info"));
    assert_eq!(info.status.code(), Some(1), "info trips --fail-on info");
}

#[test]
fn empty_cursor_or_other_mcp_json_uses_mcp_servers() {
    let dir = temp_dir("cursor");
    let cursor = dir.join(".cursor").join("mcp.json");
    fs::create_dir_all(cursor.parent().expect("parent")).expect("dir");
    fs::write(&cursor, b" \n").expect("blank");
    let output = scan(&cursor, Some("high"));
    assert!(output.status.success());
    assert_eq!(finding(&output)["suggested_fix"], OTHER_FIX);

    let other = temp_dir("other").join("mcp.json");
    fs::write(&other, "\u{feff}".as_bytes()).expect("bom");
    let output = scan(&other, Some("info"));
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(finding(&output)["suggested_fix"], OTHER_FIX);
}

#[test]
fn truncated_json_stays_high_and_names_the_parser_location() {
    let dir = temp_dir("truncated");
    let file = dir.join("mcp.json");
    fs::write(&file, b"{").expect("truncated");
    let output = scan(&file, Some("high"));
    assert_eq!(output.status.code(), Some(1));
    let found = finding(&output);
    assert_eq!(found["severity"], "high");
    let title = found["title"].as_str().expect("title");
    assert!(title.contains("Configuration file is not valid JSON:"));
    assert!(title.contains("line"));
    assert!(title.contains("column"));
    assert!(title.contains("https://balerxgate.com/docs/scan"));
    assert!(!title.contains("Configuration file is empty"));
    assert_eq!(
        found["suggested_fix"],
        "Fix the JSON or TOML syntax so the scanner can read the file"
    );
}

#[test]
fn empty_fix_follows_the_agent_config_format() {
    let cases = [
        (
            ".vscode/mcp.json",
            VSCODE_FIX,
        ),
        (
            "Library/Application Support/Code/User/mcp.json",
            VSCODE_FIX,
        ),
        (".config/Code/User/mcp.json", VSCODE_FIX),
        ("AppData/Roaming/Code/User/mcp.json", VSCODE_FIX),
        (".cursor/mcp.json", OTHER_FIX),
        (".mcp.json", OTHER_FIX),
        (".claude.json", OTHER_FIX),
        ("Claude/claude_desktop_config.json", OTHER_FIX),
        (".codeium/windsurf/mcp_config.json", OTHER_FIX),
        (
            ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
            OTHER_FIX,
        ),
        (
            ".config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings.json",
            OTHER_FIX,
        ),
        (".gemini/settings.json", OTHER_FIX),
        (
            ".claude/settings.json",
            "Delete the file or add a Claude Code settings object, for example {}. Nothing was scanned from this file.",
        ),
        (
            ".config/Code/User/settings.json",
            "Delete the file or add a VS Code settings object, for example {}. Nothing was scanned from this file.",
        ),
        (
            ".cursor/hooks.json",
            "Delete the file or add a Cursor hooks file, for example { \"version\": 1, \"hooks\": {} }. Nothing was scanned from this file.",
        ),
        (
            ".config/zed/settings.json",
            "Delete the file or add a Zed settings object, for example { \"context_servers\": {} }. Nothing was scanned from this file.",
        ),
        (
            ".continue/config.json",
            "Delete the file or add a Continue config, for example { \"mcpServers\": {} }. Nothing was scanned from this file.",
        ),
        (".codex/config.toml", CODEX_FIX),
        (".config/codex/config.toml", CODEX_FIX),
        (
            ".aider.conf.yml",
            "Delete the file or add an Aider YAML config. Aider does not use a JSON mcpServers object. Nothing was scanned from this file.",
        ),
        (
            ".config/goose/config.yaml",
            "Delete the file or add a Goose YAML config. Goose extensions are YAML, not a JSON mcpServers object. Nothing was scanned from this file.",
        ),
        (
            ".continue/config.yaml",
            "Delete the file or add a Continue YAML config. An MCP server list, when used, is mcpServers:. Nothing was scanned from this file.",
        ),
    ];
    for (rel, expected) in cases {
        let dir = temp_dir("shape");
        let file = dir.join(rel);
        fs::create_dir_all(file.parent().expect("parent")).expect("dir");
        fs::write(&file, b"\n").expect("blank");
        let output = scan(&file, Some("high"));
        assert!(
            output.status.success(),
            "{rel} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let fix = finding(&output)["suggested_fix"]
            .as_str()
            .unwrap_or("")
            .to_string();
        assert_eq!(fix, expected, "{rel}");
        let ext = std::path::Path::new(rel).extension();
        let text_config = ext.is_some_and(|value| {
            value.eq_ignore_ascii_case("toml")
                || value.eq_ignore_ascii_case("yml")
                || value.eq_ignore_ascii_case("yaml")
        });
        if text_config {
            assert!(!fix.contains('{'), "{rel} used JSON braces: {fix}");
        }
    }
}

#[test]
fn valid_vscode_json_has_no_config_finding() {
    let dir = temp_dir("valid");
    let file = dir.join("mcp.json");
    fs::write(&file, b"{\"servers\": {}}").expect("valid");
    let output = scan(&file, Some("info"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let found = finding(&output);
    assert!(found.is_null(), "{found}");
}
