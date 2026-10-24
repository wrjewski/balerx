use balerx_core::config::{inspect_contents, strip_utf8_bom, IssueType, McpConfig};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/config")
}

#[derive(Debug, Deserialize)]
struct Expected {
    file: String,
    issue_type: Option<IssueType>,
    description: Option<String>,
    description_contains: Option<Vec<String>>,
}

#[test]
fn golden_config_text_cases() {
    let dir = fixtures();
    let expected: Vec<Expected> =
        serde_json::from_str(&fs::read_to_string(dir.join("expected.json")).expect("golden"))
            .expect("golden json");
    assert!(expected.len() >= 5);
    for case in expected {
        let path = dir.join(&case.file);
        let bytes = fs::read(&path).unwrap_or_else(|_| panic!("read {}", path.display()));
        let text = String::from_utf8(bytes).unwrap_or_else(|_| panic!("utf-8 {}", case.file));
        let inspected = inspect_contents(Path::new(&case.file), &text);
        match case.issue_type {
            None => {
                assert!(
                    inspected.issues.iter().all(|issue| !matches!(
                        issue.issue_type,
                        IssueType::EmptyConfig | IssueType::BrokenConfig
                    )),
                    "{} raised {:?}",
                    case.file,
                    inspected
                        .issues
                        .iter()
                        .map(|issue| &issue.description)
                        .collect::<Vec<_>>()
                );
                assert!(inspected.mcp.is_some(), "{} should be scanned", case.file);
            }
            Some(kind) => {
                assert_eq!(
                    inspected.issues.len(),
                    1,
                    "{} issues: {:?}",
                    case.file,
                    inspected
                        .issues
                        .iter()
                        .map(|issue| issue.description.clone())
                        .collect::<Vec<_>>()
                );
                let issue = &inspected.issues[0];
                assert_eq!(issue.issue_type, kind, "{}", case.file);
                assert!(inspected.mcp.is_none(), "{} was scanned", case.file);
                if let Some(description) = &case.description {
                    assert_eq!(issue.description, *description, "{}", case.file);
                }
                for needle in case.description_contains.unwrap_or_default() {
                    assert!(
                        issue.description.contains(&needle),
                        "{} description {:?} missing {needle}",
                        case.file,
                        issue.description
                    );
                }
                if kind == IssueType::EmptyConfig {
                    assert!(issue.description.contains("Configuration file is empty"));
                    assert!(!issue.description.to_ascii_lowercase().contains("eof"));
                }
            }
        }
    }
}

#[test]
fn blank_json_and_toml_from_other_agents_are_empty() {
    for name in [
        "mcp.json",
        ".cursor/mcp.json",
        "settings.json",
        ".claude.json",
        "config.toml",
    ] {
        let inspected = inspect_contents(Path::new(name), "\u{feff}\n\t ");
        assert_eq!(inspected.issues.len(), 1, "{name}");
        assert_eq!(inspected.issues[0].issue_type, IssueType::EmptyConfig);
        assert_eq!(
            inspected.issues[0].description,
            "Configuration file is empty"
        );
        assert!(inspected.mcp.is_none());
    }
}

#[test]
fn empty_yaml_is_info_and_a_filled_yaml_file_is_left_alone() {
    for name in [".aider.conf.yml", ".config/goose/config.yaml"] {
        let inspected = inspect_contents(Path::new(name), " \n");
        assert_eq!(inspected.issues.len(), 1, "{name}");
        assert_eq!(inspected.issues[0].issue_type, IssueType::EmptyConfig);
        assert!(inspected.mcp.is_none());
    }
    let filled = inspect_contents(Path::new(".aider.conf.yml"), "model: gpt\n");
    assert!(filled.issues.is_empty());
    assert!(filled.mcp.is_none());
}

#[test]
fn bom_prefixed_json_parses() {
    let path = fixtures().join("bom-valid.json");
    let config = McpConfig::parse_file(&path).expect("BOM JSON parses");
    assert!(config.mcp_servers.is_empty());
    let text = fs::read_to_string(&path).expect("read");
    assert!(strip_utf8_bom(&text).starts_with('{'));
}
