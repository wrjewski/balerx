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
    pub line: Option<u32>,
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
            name: "OpenAI Project Key".to_string(),
            pattern: r"sk-proj-[A-Za-z0-9_-]{20,}".to_string(),
            severity: SecretSeverity::High,
        },
        SecretPattern {
            name: "OpenAI API Key".to_string(),
            pattern: r"sk-[a-zA-Z0-9]{48}".to_string(),
            severity: SecretSeverity::High,
        },
        SecretPattern {
            name: "Anthropic API Key".to_string(),
            pattern: r"sk-ant-[A-Za-z0-9_-]{20,}".to_string(),
            severity: SecretSeverity::High,
        },
        SecretPattern {
            name: "Slack Bot Token".to_string(),
            pattern: r"xox[baprs]-[A-Za-z0-9-]{10,}".to_string(),
            severity: SecretSeverity::High,
        },
        SecretPattern {
            name: "Stripe Secret Key".to_string(),
            pattern: r"sk_(?:live|test)_[A-Za-z0-9]{10,}".to_string(),
            severity: SecretSeverity::High,
        },
        SecretPattern {
            name: "GitHub Fine-Grained PAT".to_string(),
            pattern: r"github_pat_[A-Za-z0-9_]{20,}".to_string(),
            severity: SecretSeverity::High,
        },
        SecretPattern {
            name: "URL Password".to_string(),
            pattern: r"(?i)[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]{8,}@[^\s]+".to_string(),
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
        let mut specific_spans = Vec::new();

        for (name, regex, severity) in &self.patterns {
            if let Ok(Some(mat)) = regex.find(text) {
                if is_generic(name)
                    && specific_spans
                        .iter()
                        .any(|(start, end)| mat.start() < *end && mat.end() > *start)
                {
                    continue;
                }
                if !is_generic(name) {
                    specific_spans.push((mat.start(), mat.end()));
                }
                let matched_text = mat.as_str();
                let redacted = redact_secret(matched_text);
                let line = u32::try_from(
                    text[..mat.start()]
                        .bytes()
                        .filter(|byte| *byte == b'\n')
                        .count()
                        + 1,
                )
                .ok();

                matches.push(SecretMatch {
                    pattern_name: name.clone(),
                    redacted_value: redacted,
                    location: location.to_string(),
                    severity: *severity,
                    line,
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
                    let nested_location = format!("{location}.{key}");
                    if let serde_json::Value::String(text) = value {
                        matches.extend(self.scan_text(&format!("{key}={text}"), &nested_location));
                    } else {
                        matches.extend(self.scan_json(value, &nested_location));
                    }
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

fn is_generic(name: &str) -> bool {
    name.starts_with("Generic ")
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
