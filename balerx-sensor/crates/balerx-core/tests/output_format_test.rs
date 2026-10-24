use balerx_core::{
    agent::{Agent, AgentDefinition, AgentStatus},
    finding::{Finding, FindingSeverity, ScanResult},
    output::{write_html, write_json, write_sarif},
    rules::{hook_gap_install_fix, RuleId},
};
use std::path::PathBuf;

#[test]
fn test_json_output_format() {
    let mut result = ScanResult::new();

    let _def = AgentDefinition::builtin_definitions()
        .into_iter()
        .find(|d| d.id == "cursor")
        .expect("Cursor definition should exist");

    let agent = Agent {
        name: "Cursor".to_string(),
        definition_id: "cursor".to_string(),
        config_paths: vec![PathBuf::from("/home/test/.cursor/mcp.json")],
        version: None,
        path: None,
        status: AgentStatus::Configured,
        process_id: None,
        guard_coverage: None,
    };

    result.add_agent(agent);

    let finding = Finding::new(
        RuleId::McpSupplyUnpinned,
        FindingSeverity::Medium,
        "Unpinned npm package".to_string(),
        "MCP server uses unpinned npm package".to_string(),
    )
    .with_agent("Cursor")
    .with_resource("/home/test/.cursor/mcp.json");

    result.add_finding(finding);

    let temp_dir = std::env::temp_dir();
    let json_path = temp_dir.join("balerx_test_output.json");

    write_json(&result, &json_path).expect("Should write JSON");

    let content = std::fs::read_to_string(&json_path).expect("Should read JSON");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("Should parse JSON");

    assert!(parsed["scan_id"].is_string(), "scan_id should be a string");
    assert!(
        parsed["scanned_at"].is_string(),
        "scanned_at should be a string"
    );
    assert_eq!(parsed["schema_version"].as_str().unwrap(), "1.0.0");
    assert_eq!(parsed["agents"].as_array().unwrap().len(), 1);
    assert_eq!(parsed["findings"].as_array().unwrap().len(), 1);
    assert!(parsed["summary"].is_object());

    std::fs::remove_file(json_path).ok();
}

#[test]
fn test_sarif_output_format() {
    let mut result = ScanResult::new();

    let _def = AgentDefinition::builtin_definitions()
        .into_iter()
        .find(|d| d.id == "cursor")
        .expect("Cursor definition should exist");

    let agent = Agent {
        name: "Cursor".to_string(),
        definition_id: "cursor".to_string(),
        config_paths: vec![PathBuf::from("/home/test/.cursor/mcp.json")],
        version: None,
        path: None,
        status: AgentStatus::Configured,
        process_id: None,
        guard_coverage: None,
    };

    result.add_agent(agent);

    let finding = Finding::new(
        RuleId::McpSupplyUnpinned,
        FindingSeverity::Medium,
        "Unpinned npm package".to_string(),
        "MCP server uses unpinned npm package".to_string(),
    )
    .with_agent("Cursor")
    .with_resource("/home/test/.cursor/mcp.json");

    result.add_finding(finding);

    let temp_dir = std::env::temp_dir();
    let sarif_path = temp_dir.join("balerx_test_output.sarif");

    write_sarif(&result, &sarif_path).expect("Should write SARIF");

    let content = std::fs::read_to_string(&sarif_path).expect("Should read SARIF");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("Should parse SARIF");

    assert_eq!(parsed["version"].as_str().unwrap(), "2.1.0");
    let schema = parsed["$schema"].as_str().unwrap();
    assert!(
        schema.contains("sarif") && schema.contains("2.1"),
        "SARIF schema should reference version 2.1"
    );
    assert!(parsed["runs"].is_array());

    let runs = parsed["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);

    let run = &runs[0];
    assert!(run["tool"].is_object());
    assert!(run["results"].is_array());

    let tool = &run["tool"];
    assert_eq!(tool["driver"]["name"].as_str().unwrap(), "Balerx Gate");
    assert_eq!(
        tool["driver"]["informationUri"].as_str().unwrap(),
        "https://github.com/wrjewski/balerx",
        "SARIF links to the public scanner repository"
    );
    assert_public_scanner_urls(&content);

    let results = run["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);

    std::fs::remove_file(sarif_path).ok();
}

#[test]
fn test_sarif_schema_compliance() {
    let mut result = ScanResult::new();

    let finding = Finding::new(
        RuleId::SecretInConfig,
        FindingSeverity::Critical,
        "API key in config".to_string(),
        "Found API key in configuration".to_string(),
    );

    result.add_finding(finding);

    let temp_dir = std::env::temp_dir();
    let sarif_path = temp_dir.join("balerx_schema_test.sarif");

    write_sarif(&result, &sarif_path).expect("Should write SARIF");

    let content = std::fs::read_to_string(&sarif_path).expect("Should read SARIF");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("Should parse SARIF");

    assert!(parsed["version"].is_string());
    assert!(parsed["$schema"].is_string());
    assert!(parsed["runs"].is_array());

    for run in parsed["runs"].as_array().unwrap() {
        assert!(run["tool"].is_object());
        assert!(run["tool"]["driver"].is_object());
        assert!(run["tool"]["driver"]["name"].is_string());
        assert!(run["results"].is_array());

        for result in run["results"].as_array().unwrap() {
            assert!(result["ruleId"].is_string());
            assert!(result["level"].is_string());
            assert!(result["message"].is_object());
            assert!(result["message"]["text"].is_string());
        }
    }

    std::fs::remove_file(sarif_path).ok();
}

#[test]
fn test_json_roundtrip() {
    let mut result = ScanResult::new();

    let finding = Finding::new(
        RuleId::McpPermBroadFilesystem,
        FindingSeverity::High,
        "Broad filesystem access".to_string(),
        "MCP server has access to root filesystem".to_string(),
    )
    .with_resource("/")
    .with_fix("Restrict access to specific directories");

    result.add_finding(finding);

    let temp_dir = std::env::temp_dir();
    let json_path = temp_dir.join("balerx_roundtrip.json");

    write_json(&result, &json_path).expect("Should write JSON");

    let content = std::fs::read_to_string(&json_path).expect("Should read JSON");
    let parsed: ScanResult = serde_json::from_str(&content).expect("Should deserialize");

    assert_eq!(parsed.findings.len(), result.findings.len());
    assert_eq!(parsed.summary.findings_count, 1);

    std::fs::remove_file(json_path).ok();
}

fn assert_public_scanner_urls(content: &str) {
    let public_url = "https://github.com/wrjewski/balerx";
    let marker = "github.com/";
    let public_tail = public_url.trim_start_matches("https://");
    let mut start = 0;
    let mut seen = false;
    while let Some(index) = content[start..].find(marker) {
        let at = start + index;
        let rest = &content[at..];
        assert!(
            rest.starts_with(public_tail),
            "SARIF may only link the public scanner repository"
        );
        let after = &rest[public_tail.len()..];
        assert!(
            after.is_empty()
                || after
                    .starts_with(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_'),
            "SARIF may only link the public scanner repository"
        );
        seen = true;
        start = at + public_tail.len();
    }
    assert!(seen, "SARIF should link the public scanner repository");
    assert!(content.contains(public_url));
}

#[test]
fn sarif_uri_outside_the_working_directory_is_home_relative() {
    let home = balerx_core::agent::home_dir().expect("home");
    let resource = home.join(".cursor").join("mcp.json");
    let mut result = ScanResult::new();
    result.add_finding(
        Finding::new(
            RuleId::McpRemotePlainHttp,
            FindingSeverity::High,
            "Plain HTTP".to_string(),
            "Remote MCP URL".to_string(),
        )
        .with_resource(resource.to_string_lossy().into_owned()),
    );
    let sarif_path = std::env::temp_dir().join("balerx_home_uri.sarif");
    write_sarif(&result, &sarif_path).expect("write");
    let content = std::fs::read_to_string(&sarif_path).expect("read");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("json");
    let uri = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        ["artifactLocation"]["uri"]
        .as_str()
        .expect("uri");
    assert_eq!(uri, "~/.cursor/mcp.json");
    assert_public_scanner_urls(&content);
    std::fs::remove_file(sarif_path).ok();
}

#[test]
fn hook_gap_fix_is_the_same_in_json_sarif_and_html() {
    let claude = hook_gap_install_fix("claude-code").expect("claude fix");
    let cursor = hook_gap_install_fix("cursor").expect("cursor fix");
    assert_eq!(
        claude,
        "Run: balerx guard install claude-code\nMore: https://balerxgate.com/docs/guard"
    );
    assert_eq!(
        cursor,
        "Run: balerx guard install cursor\nMore: https://balerxgate.com/docs/guard"
    );
    assert!(hook_gap_install_fix("claude").is_none());
    assert!(hook_gap_install_fix("Claude Code").is_none());

    let mut result = ScanResult::new();
    result.add_finding(
        Finding::new(
            RuleId::HookGapNoGuard,
            FindingSeverity::Medium,
            "Guard hooks are not installed for Claude Code".to_string(),
            "This agent has a config file and no Balerx hook entry".to_string(),
        )
        .with_agent("Claude Code")
        .with_resource("/tmp/claude/settings.json")
        .with_fix(claude.clone()),
    );

    let dir = std::env::temp_dir().join(format!("balerx-hook-gap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let json_path = dir.join("scan.json");
    let sarif_path = dir.join("scan.sarif");
    let html_path = dir.join("scan.html");
    write_json(&result, &json_path).expect("json");
    write_sarif(&result, &sarif_path).expect("sarif");
    write_html(&result, &html_path).expect("html");

    let json = std::fs::read_to_string(&json_path).expect("read json");
    let sarif = std::fs::read_to_string(&sarif_path).expect("read sarif");
    let html = std::fs::read_to_string(&html_path).expect("read html");
    for report in [&json, &sarif, &html] {
        assert!(report.contains("Run: balerx guard install claude-code"));
        assert!(report.contains("More: https://balerxgate.com/docs/guard"));
        assert!(!report.contains("for this agent"));
    }
    let parsed_json: serde_json::Value = serde_json::from_str(&json).expect("json");
    assert_eq!(
        parsed_json["findings"][0]["suggested_fix"].as_str(),
        Some(claude.as_str())
    );
    let parsed_sarif: serde_json::Value = serde_json::from_str(&sarif).expect("sarif json");
    let message = parsed_sarif["runs"][0]["results"][0]["message"]["text"]
        .as_str()
        .expect("message");
    assert!(message.ends_with(&claude));
    assert!(html.contains(
        "Suggested Fix:</strong> Run: balerx guard install claude-code<br>More: https://balerxgate.com/docs/guard"
    ));
    std::fs::remove_dir_all(&dir).ok();
}
