use fancy_regex::Regex;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPattern {
    pub name: String,
    pub pattern: String,
    pub severity: SecretSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretSeverity {
    Critical,
    High,
    Medium,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMatch {
    pub pattern_name: String,
    pub redacted_value: String,
    pub location: String,
    pub severity: SecretSeverity,
}

static SECRET_PATTERNS: Lazy<Vec<SecretPattern>> = Lazy::new(|| {
    vec![
        SecretPattern {
            name: "AWS Access Key".to_string(),
            pattern: r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
                .to_string(),
            severity: SecretSeverity::Critical,
        },
        SecretPattern {
            name: "AWS Secret Key".to_string(),
            pattern: r#"(?i)aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]"#.to_string(),
            severity: SecretSeverity::Critical,
        },
        SecretPattern {
            name: "GitHub Token".to_string(),
            pattern: r"gh[pousr]_[0-9a-zA-Z]{36}".to_string(),
            severity: SecretSeverity::High,
        },
        SecretPattern {
            name: "OpenAI API Key".to_string(),
            pattern: r"sk-[a-zA-Z0-9]{48}".to_string(),
            severity: SecretSeverity::High,
        },
        SecretPattern {
            name: "Anthropic API Key".to_string(),
            pattern: r"sk-ant-[a-zA-Z0-9\-]{95,}".to_string(),
            severity: SecretSeverity::High,
        },
        SecretPattern {
            name: "Generic API Key".to_string(),
            pattern: r#"(?i)(api[_\-]?key|apikey)['"\s]*[:=]['"\s]*[a-zA-Z0-9\-_]{20,}"#
                .to_string(),
            severity: SecretSeverity::Medium,
        },
        SecretPattern {
            name: "Generic Secret".to_string(),
            pattern:
                r#"(?i)(secret|password|passwd|pwd)['"\s]*[:=]['"\s]*[a-zA-Z0-9\-_!@#$%^&*()]{8,}"#
                    .to_string(),
            severity: SecretSeverity::Medium,
        },
    ]
});

pub struct SecretDetector {
    patterns: Vec<(String, Regex, SecretSeverity)>,
}

impl SecretDetector {
    /// Create a new secret detector
    ///
    /// # Errors
    /// Returns an error if regex patterns cannot be compiled
    pub fn new() -> anyhow::Result<Self> {
        let mut patterns = Vec::new();

        for pattern_def in SECRET_PATTERNS.iter() {
            let regex = Regex::new(&pattern_def.pattern)?;
            patterns.push((pattern_def.name.clone(), regex, pattern_def.severity));
        }

        Ok(Self { patterns })
    }

    #[must_use]
    pub fn scan_text(&self, text: &str, location: &str) -> Vec<SecretMatch> {
        let mut matches = Vec::new();

        for (name, regex, severity) in &self.patterns {
            if let Ok(Some(mat)) = regex.find(text) {
                let matched_text = mat.as_str();
                let redacted = redact_secret(matched_text);

                matches.push(SecretMatch {
                    pattern_name: name.clone(),
                    redacted_value: redacted,
                    location: location.to_string(),
                    severity: *severity,
                });
            }
        }

        matches
    }

    #[must_use]
    pub fn scan_json(&self, json: &serde_json::Value, location: &str) -> Vec<SecretMatch> {
        let mut matches = Vec::new();

        match json {
            serde_json::Value::String(s) => {
                matches.extend(self.scan_text(s, location));
            }
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    let key_lower = key.to_lowercase();
                    if key_lower.contains("secret")
                        || key_lower.contains("password")
                        || key_lower.contains("token")
                        || key_lower.contains("key")
                    {
                        if let serde_json::Value::String(s) = value {
                            matches.extend(self.scan_text(s, &format!("{location}.{key}")));
                        }
                    }

                    let nested_location = format!("{location}.{key}");
                    matches.extend(self.scan_json(value, &nested_location));
                }
            }
            serde_json::Value::Array(arr) => {
                for (idx, value) in arr.iter().enumerate() {
                    let nested_location = format!("{location}[{idx}]");
                    matches.extend(self.scan_json(value, &nested_location));
                }
            }
            _ => {}
        }

        matches
    }
}

impl Default for SecretDetector {
    fn default() -> Self {
        Self::new().expect("Failed to compile secret patterns")
    }
}

fn redact_secret(value: &str) -> String {
    if value.len() <= 8 {
        "***REDACTED***".to_string()
    } else {
        let prefix_len = value.len().min(4);
        let prefix = &value[..prefix_len];
        format!("{prefix}***REDACTED***")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_key_detection() {
        let detector = SecretDetector::new().unwrap();
        let key = crate::canary::synthetic_aws_example_access_key();
        let text = format!("AWS_ACCESS_KEY_ID={key}");
        let matches = detector.scan_text(&text, "test");
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "AWS Access Key");
    }

    #[test]
    fn test_redaction() {
        let secret = crate::canary::synthetic_aws_example_access_key();
        let redacted = redact_secret(&secret);
        assert!(redacted.starts_with("AKIA"));
        assert!(redacted.contains("REDACTED"));
        assert!(!redacted.contains(&secret[4..]));
    }
}
