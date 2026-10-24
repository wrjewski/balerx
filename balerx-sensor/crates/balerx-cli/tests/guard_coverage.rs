use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "balerx-coverage-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

const VSCODE_NOTE: &str = "Guard hooks are not available for VS Code with GitHub Copilot yet, so its tool calls aren't intercepted. The scan still checks its config.";
const CODEX_NOTE: &str = "Guard hooks are not available for Codex CLI yet, so its tool calls aren't intercepted. The scan still checks its config.";

#[test]
fn uncovered_agents_get_a_coverage_line_without_a_finding() {
    let home = temp_dir("home");
    let work = temp_dir("work");
    let vscode = work.join(".vscode/mcp.json");
    fs::create_dir_all(vscode.parent().expect("vscode parent")).expect("vscode dir");
    fs::write(&vscode, "{\"servers\": {}}\n").expect("vscode config");
    let codex = home.join(".codex/config.toml");
    fs::create_dir_all(codex.parent().expect("codex parent")).expect("codex dir");
    fs::write(&codex, "model = \"gpt-5\"\n").expect("codex config");

    let json = work.join("scan.json");
    let sarif = work.join("scan.sarif");
    let html = work.join("scan.html");
    let output = Command::new(env!("CARGO_BIN_EXE_balerx"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .current_dir(&work)
        .args([
            "scan",
            "--quiet",
            "--fail-on",
            "info",
            "--format",
            "text",
            "--json",
            json.to_str().expect("json path"),
            "--sarif",
            sarif.to_str().expect("sarif path"),
            "--html",
            html.to_str().expect("html path"),
        ])
        .output()
        .expect("run scan");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "coverage must not trip --fail-on info: {}\n{text}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains(&format!("Guard coverage: {VSCODE_NOTE}")));
    assert!(text.contains(&format!("Guard coverage: {CODEX_NOTE}")));
    assert!(!text.contains("not available for Claude Code"));
    assert!(!text.contains("not available for Cursor"));
    assert!(!text.contains("HOOK-GAP"));

    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&json).expect("json")).expect("parse json");
    assert_eq!(parsed["summary"]["findings_count"], 0);
    assert_eq!(parsed["summary"]["info_count"], 0);
    assert_eq!(parsed["summary"]["risk_score"], 0);
    assert_eq!(parsed["findings"].as_array().expect("findings").len(), 0);
    let agents = parsed["agents"].as_array().expect("agents");
    assert_eq!(agents.len(), 2);
    for (id, note) in [("vscode-copilot", VSCODE_NOTE), ("codex-cli", CODEX_NOTE)] {
        let agent = agents
            .iter()
            .find(|agent| agent["definition_id"] == id)
            .unwrap_or_else(|| panic!("missing {id}"));
        assert_eq!(agent["guard_coverage"], note);
    }

    let sarif_text = fs::read_to_string(&sarif).expect("sarif");
    let sarif_json: serde_json::Value = serde_json::from_str(&sarif_text).expect("parse sarif");
    let run = &sarif_json["runs"][0];
    assert_eq!(run["results"].as_array().expect("results").len(), 0);
    let notes = run["properties"]["guardCoverage"]
        .as_array()
        .expect("guardCoverage");
    assert!(notes.iter().any(|note| note == VSCODE_NOTE));
    assert!(notes.iter().any(|note| note == CODEX_NOTE));
    assert!(!sarif_text.contains("HOOK-GAP"));
    assert!(!sarif_text.contains("\"ruleId\""));

    let html_text = fs::read_to_string(&html).expect("html");
    assert!(html_text.contains("Guard coverage:"));
    assert!(html_text.contains("VS Code with GitHub Copilot"));
    assert!(html_text.contains("Codex CLI"));
    assert!(html_text.contains("The scan still checks its config."));
    assert!(html_text.contains("aren&#x27;t"));
    assert!(!html_text.contains("HOOK-GAP"));

    let _ = fs::remove_dir_all(home);
    let _ = fs::remove_dir_all(work);
}
