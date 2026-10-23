use balerx_core::canary::{
    synthetic_anthropic_key, synthetic_aws_example_access_key, synthetic_github_token,
    synthetic_openai_key,
};
use balerx_core::secret::{SecretDetector, SecretSeverity};

#[test]
fn test_detect_aws_access_key() {
    let detector = SecretDetector::new().expect("Should create detector");
    let text = format!("AWS_ACCESS_KEY_ID={}", synthetic_aws_example_access_key());

    let matches = detector.scan_text(&text, "test");
    assert!(!matches.is_empty(), "Should detect AWS access key");

    let m = &matches[0];
    assert_eq!(m.pattern_name, "AWS Access Key");
    assert_eq!(m.severity, SecretSeverity::Critical);
}

#[test]
fn test_detect_github_token() {
    let detector = SecretDetector::new().expect("Should create detector");
    // GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_ followed by 36 alphanumeric.
    // The fixture is joined at runtime so the source has no complete token.
    let text = format!("token: {}", synthetic_github_token());

    let matches = detector.scan_text(&text, "test");
    assert!(!matches.is_empty(), "Should detect GitHub token");

    let m = &matches[0];
    assert_eq!(m.pattern_name, "GitHub Token");
}

#[test]
fn test_detect_openai_key() {
    let detector = SecretDetector::new().expect("Should create detector");
    // OpenAI keys are sk- followed by 48 alphanumeric characters.
    let text = synthetic_openai_key();

    let matches = detector.scan_text(&text, "test");
    assert!(!matches.is_empty(), "Should detect OpenAI key");

    let m = &matches[0];
    assert_eq!(m.pattern_name, "OpenAI API Key");
}

#[test]
fn test_detect_anthropic_key() {
    let detector = SecretDetector::new().expect("Should create detector");
    // Anthropic keys: sk-ant- followed by letters, digits, hyphens, or underscores.
    let text = synthetic_anthropic_key();

    let matches = detector.scan_text(&text, "test");
    assert!(!matches.is_empty(), "Should detect Anthropic key");

    let m = &matches[0];
    assert_eq!(m.pattern_name, "Anthropic API Key");
}

#[test]
fn test_redaction() {
    let detector = SecretDetector::new().expect("Should create detector");
    let text = synthetic_aws_example_access_key();

    let matches = detector.scan_text(&text, "test");
    assert!(!matches.is_empty());

    let redacted = &matches[0].redacted_value;
    assert!(redacted.starts_with("AKIA"), "Should keep prefix");
    assert!(redacted.contains("REDACTED"), "Should contain REDACTED");
    assert!(!redacted.contains("EXAMPLE"), "Should not contain full key");
}

#[test]
fn test_scan_json_fixture_openai() {
    let detector = SecretDetector::new().expect("Should create detector");
    let json = serde_json::json!({
        "apiKey": synthetic_openai_key(),
        "model": "gpt-4"
    });

    let matches = detector.scan_json(&json, "test");
    assert!(!matches.is_empty(), "Should detect OpenAI key in JSON");
}

#[test]
fn test_scan_json_fixture_anthropic() {
    let detector = SecretDetector::new().expect("Should create detector");
    let json = serde_json::json!({
        "apiKey": synthetic_anthropic_key()
    });

    let matches = detector.scan_json(&json, "test");
    assert!(!matches.is_empty(), "Should detect Anthropic key in JSON");
}

#[test]
fn test_scan_json_nested() {
    let detector = SecretDetector::new().expect("Should create detector");

    let json = serde_json::json!({
        "config": {
            "auth": {
                "github_token": synthetic_github_token()
            }
        }
    });

    let matches = detector.scan_json(&json, "test");
    assert!(!matches.is_empty(), "Should detect secret in nested JSON");
}

#[test]
fn test_scan_claude_code_fixture() {
    let detector = SecretDetector::new().expect("Should create detector");
    let json = serde_json::json!({
        "mcpServers": {
            "aws": {
                "command": "npx",
                "args": ["-y", "mcp-server-aws"],
                "env": {
                    "AWS_ACCESS_KEY_ID": synthetic_aws_example_access_key(),
                    "AWS_SECRET_ACCESS_KEY": "not-a-provider-key"
                }
            }
        }
    });

    let matches = detector.scan_json(&json, "test");

    let aws_key = matches.iter().find(|m| m.pattern_name == "AWS Access Key");
    assert!(aws_key.is_some(), "Should detect AWS access key");
}
