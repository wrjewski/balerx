use balerx_core::config::{IssueType, McpConfig};
use std::path::PathBuf;

#[test]
fn test_parse_mcp_config_with_unpinned_package() {
    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cursor/mcp.json");

    let config = McpConfig::parse_file(&fixture_path).expect("Should parse fixture config");

    assert!(!config.mcp_servers.is_empty(), "Should have servers");
    assert!(config.mcp_servers.contains_key("unpinned-package"));
}

#[test]
fn test_detect_unpinned_package() {
    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cursor/mcp.json");

    let config = McpConfig::parse_file(&fixture_path).expect("Should parse fixture config");

    let issues = config.find_issues();

    let unpinned = issues
        .iter()
        .find(|i| i.issue_type == IssueType::UnpinnedPackage);
    assert!(unpinned.is_some(), "Should detect unpinned package");
}

#[test]
fn test_detect_latest_tag() {
    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cursor/mcp.json");

    let config = McpConfig::parse_file(&fixture_path).expect("Should parse fixture config");

    let issues = config.find_issues();

    eprintln!("All issues found:");
    for issue in &issues {
        eprintln!(
            "  - {:?}: {} (server: {})",
            issue.issue_type, issue.description, issue.server_name
        );
    }

    let latest = issues.iter().find(|i| i.issue_type == IssueType::LatestTag);
    assert!(
        latest.is_some(),
        "Should detect @latest tag. Found {} issues total",
        issues.len()
    );
    assert_eq!(latest.unwrap().server_name, "latest-tag");
}

#[test]
fn test_detect_plain_http() {
    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cursor/mcp.json");

    let config = McpConfig::parse_file(&fixture_path).expect("Should parse fixture config");

    let issues = config.find_issues();

    let plain_http = issues.iter().find(|i| i.issue_type == IssueType::PlainHttp);
    assert!(plain_http.is_some(), "Should detect plain HTTP");
}

#[test]
fn test_detect_broad_filesystem() {
    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cursor/mcp.json");

    let config = McpConfig::parse_file(&fixture_path).expect("Should parse fixture config");

    let issues = config.find_issues();

    let broad_fs = issues
        .iter()
        .find(|i| i.issue_type == IssueType::BroadFilesystem);
    assert!(broad_fs.is_some(), "Should detect broad filesystem access");
    assert_eq!(broad_fs.unwrap().resource, "/");
}

#[test]
fn test_ignore_localhost_http() {
    let json = r#"{
        "mcpServers": {
            "local": {
                "url": "http://localhost:8080"
            }
        }
    }"#;

    let config: McpConfig = serde_json::from_str(json).expect("Should parse");
    let issues = config.find_issues();

    let plain_http = issues.iter().find(|i| i.issue_type == IssueType::PlainHttp);
    assert!(plain_http.is_none(), "Should ignore localhost HTTP");
}
