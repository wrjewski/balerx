use balerx_core::{
    agent::{Agent, AgentDefinition, AgentStatus},
    finding::{Finding, FindingSeverity, ScanResult},
    output::{write_json, write_sarif},
    rules::RuleId,
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
    let private_repo = format!("{}-{}", "balerxgate", "dev");
    assert!(
        !content.contains(&private_repo),
        "SARIF must not point at the private development repository"
    );

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
