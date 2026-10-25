use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default = "default_version")]
    pub version: String,

    #[serde(default)]
    pub global: GlobalSettings,

    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

fn default_version() -> String {
    "1.0.0".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSettings {
    #[serde(default = "default_fail_open")]
    pub fail_open: bool,

    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            fail_open: default_fail_open(),
            timeout_ms: default_timeout_ms(),
        }
    }
}

fn default_fail_open() -> bool {
    true
}

fn default_timeout_ms() -> u64 {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub description: String,
    pub enabled: bool,
    pub action: PolicyAction,
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Allow,
    Deny,
    Ask,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    PathPattern { pattern: String },
    CommandPattern { pattern: String },
    ServerAllowlist { servers: Vec<String> },
    ServerDenylist { servers: Vec<String> },
    ResourceType { types: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookEvent {
    pub event_type: HookEventType,
    pub agent: String,
    pub resource: Option<String>,
    pub command: Option<String>,
    pub mcp_server: Option<String>,
    pub tool_name: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookEventType {
    ShellExecution,
    McpExecution,
    FileRead,
    FileWrite,
    ToolCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub action: PolicyAction,
    pub reason: String,
    pub matched_rule: Option<String>,
}

impl Policy {
    #[must_use]
    pub fn default_policy() -> Self {
        Self {
            version: "1.0.0".to_string(),
            global: GlobalSettings::default(),
            rules: Self::default_rules(),
        }
    }

    #[must_use]
    fn default_rules() -> Vec<PolicyRule> {
        vec![
            PolicyRule {
                id: "deny_ssh_keys".to_string(),
                description: "Deny reading SSH private keys".to_string(),
                enabled: true,
                action: PolicyAction::Deny,
                conditions: vec![Condition::PathPattern {
                    pattern: "**/.ssh/id_*".to_string(),
                }],
            },
            PolicyRule {
                id: "deny_env_files".to_string(),
                description: "Deny reading .env files".to_string(),
                enabled: true,
                action: PolicyAction::Deny,
                conditions: vec![Condition::PathPattern {
                    pattern: "**/.env*".to_string(),
                }],
            },
            PolicyRule {
                id: "deny_pem_files".to_string(),
                description: "Deny reading .pem certificate files".to_string(),
                enabled: true,
                action: PolicyAction::Deny,
                conditions: vec![Condition::PathPattern {
                    pattern: "**/*.pem".to_string(),
                }],
            },
            PolicyRule {
                id: "deny_curl_pipe_sh".to_string(),
                description: "Deny curl | sh pattern".to_string(),
                enabled: true,
                action: PolicyAction::Deny,
                conditions: vec![Condition::CommandPattern {
                    pattern: r"curl.*\|.*sh".to_string(),
                }],
            },
            PolicyRule {
                id: "ask_force_push".to_string(),
                description: "Ask before git push --force".to_string(),
                enabled: true,
                action: PolicyAction::Ask,
                conditions: vec![Condition::CommandPattern {
                    pattern: r"git\s+push.*--force".to_string(),
                }],
            },
            PolicyRule {
                id: "deny_unapproved_mcp".to_string(),
                description: "Deny unapproved MCP servers".to_string(),
                enabled: false,
                action: PolicyAction::Deny,
                conditions: vec![Condition::ServerDenylist {
                    servers: vec!["*".to_string()],
                }],
            },
        ]
    }

    /// Parses a policy document.
    ///
    /// Empty, whitespace-only, comment-only, or YAML-null text is rejected.
    /// A missing file is handled by [`inspect_file`]; this function is for
    /// present content only.
    ///
    /// # Errors
    ///
    /// Returns an error if `yaml` is empty or is not a Balerx policy document.
    pub fn from_yaml_str(yaml: &str) -> Result<Self> {
        if is_blank_policy_yaml(yaml) {
            anyhow::bail!("Policy file is empty");
        }
        serde_yaml::from_str(strip_bom(yaml)).context("Failed to parse policy YAML")
    }

    /// Loads a policy from a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, is empty, or is not YAML.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read policy file: {}", path.display()))?;
        Self::from_yaml_str(&content)
            .with_context(|| format!("Failed to parse policy file: {}", path.display()))
    }

    /// Classifies a policy path for hook and doctor use.
    ///
    /// A missing path is [`PolicyFile::Missing`]. A present empty or
    /// unparseable file is not treated as the built-in default.
    #[must_use]
    pub fn inspect_file(path: Option<&Path>) -> PolicyFile {
        let Some(path) = path else {
            return PolicyFile::Missing;
        };
        if !path.exists() {
            return PolicyFile::Missing;
        }
        match fs::read_to_string(path) {
            Ok(content) => {
                if is_blank_policy_yaml(&content) {
                    return PolicyFile::Empty {
                        path: path.to_path_buf(),
                    };
                }
                match Self::from_yaml_str(&content) {
                    Ok(policy) => PolicyFile::Loaded(policy),
                    Err(error) => PolicyFile::Invalid {
                        path: path.to_path_buf(),
                        message: error.to_string(),
                    },
                }
            }
            Err(error) => PolicyFile::Invalid {
                path: path.to_path_buf(),
                message: error.to_string(),
            },
        }
    }

    /// Saves the policy to a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy cannot be serialized or written to disk.
    pub fn to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let content = serde_yaml::to_string(self).context("Failed to serialize policy")?;

        fs::write(path.as_ref(), content)
            .with_context(|| format!("Failed to write policy file: {}", path.as_ref().display()))
    }

    /// Evaluates the event against every path found in the resource and command.
    #[must_use]
    pub fn evaluate_event(&self, event: &HookEvent) -> PolicyDecision {
        let mut paths = Vec::new();
        if let Some(resource) = &event.resource {
            paths.push(resource.clone());
        }
        if let Some(extra) = event
            .metadata
            .get("extra_paths")
            .and_then(serde_json::Value::as_array)
        {
            for value in extra {
                if let Some(path) = value.as_str() {
                    paths.push(path.to_string());
                }
            }
        }
        if let Some(command) = &event.command {
            for token in crate::hook_input::shell_tokens(command) {
                if crate::hook_input::looks_like_path(&token) {
                    paths.push(crate::hook_input::expand_user_path(&token));
                }
            }
        }
        if paths.is_empty() {
            return self.evaluate(event);
        }
        let mut best: Option<PolicyDecision> = None;
        for path in paths {
            let mut clone = event.clone();
            clone.resource = Some(path);
            let decision = self.evaluate(&clone);
            best = Some(match best {
                Some(current) if action_rank(current.action) >= action_rank(decision.action) => {
                    current
                }
                _ => decision,
            });
        }
        best.unwrap_or_else(|| self.evaluate(event))
    }

    #[must_use]
    pub fn evaluate(&self, event: &HookEvent) -> PolicyDecision {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if Self::matches_rule(rule, event) {
                return PolicyDecision {
                    action: rule.action,
                    reason: rule.description.clone(),
                    matched_rule: Some(rule.id.clone()),
                };
            }
        }

        PolicyDecision {
            action: PolicyAction::Allow,
            reason: "No matching policy rule".to_string(),
            matched_rule: None,
        }
    }

    fn matches_rule(rule: &PolicyRule, event: &HookEvent) -> bool {
        rule.conditions
            .iter()
            .all(|condition| Self::matches_condition(condition, event))
    }

    fn matches_condition(condition: &Condition, event: &HookEvent) -> bool {
        match condition {
            Condition::PathPattern { pattern } => event
                .resource
                .as_deref()
                .is_some_and(|resource| path_matches(pattern, resource)),
            Condition::CommandPattern { pattern } => {
                if let Some(command) = &event.command {
                    regex::Regex::new(pattern).is_ok_and(|re| re.is_match(command))
                } else {
                    false
                }
            }
            Condition::ServerAllowlist { servers } => {
                if let Some(server) = &event.mcp_server {
                    servers.iter().any(|s| s == server)
                } else {
                    false
                }
            }
            Condition::ServerDenylist { servers } => {
                if let Some(server) = &event.mcp_server {
                    if servers.contains(&"*".to_string()) {
                        return true;
                    }
                    servers.iter().any(|s| s == server)
                } else {
                    false
                }
            }
            Condition::ResourceType { types } => {
                types.iter().any(|t| event.event_type.matches_type(t))
            }
        }
    }
}

/// How a policy path resolved for hook evaluation and `balerx doctor`.
#[derive(Debug)]
pub enum PolicyFile {
    /// No file at the path. The built-in default policy applies.
    Missing,
    /// Present and parseable.
    Loaded(Policy),
    /// Present but empty, whitespace-only, comment-only, or YAML-null.
    Empty { path: PathBuf },
    /// Present but unreadable or not a policy document.
    Invalid { path: PathBuf, message: String },
}

fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

fn is_blank_policy_yaml(yaml: &str) -> bool {
    let yaml = strip_bom(yaml);
    if yaml.trim().is_empty() {
        return true;
    }
    matches!(
        serde_yaml::from_str::<serde_yaml::Value>(yaml),
        Ok(serde_yaml::Value::Null)
    )
}

fn action_rank(action: PolicyAction) -> u8 {
    match action {
        PolicyAction::Deny => 3,
        PolicyAction::Ask => 2,
        PolicyAction::Allow => 1,
    }
}

fn path_matches(pattern: &str, resource: &str) -> bool {
    let resource = resource.replace('\\', "/");
    if glob::Pattern::new(pattern).is_ok_and(|compiled| compiled.matches(&resource)) {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("**/") {
        if !suffix.contains('*')
            && !suffix.contains('?')
            && (resource == suffix || resource.ends_with(&format!("/{suffix}")))
        {
            return true;
        }
    }
    let name = resource.rsplit('/').next().unwrap_or(resource.as_str());
    if pattern.contains(".env") && (name == ".env" || name.starts_with(".env.")) {
        return true;
    }
    if pattern.contains(".ssh/id_") && resource.contains(".ssh/id_") {
        return true;
    }
    if pattern.contains("*.pem")
        && name
            .rsplit_once('.')
            .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("pem"))
    {
        return true;
    }
    false
}

impl HookEventType {
    fn matches_type(self, type_name: &str) -> bool {
        matches!(
            (self, type_name),
            (Self::ShellExecution, "shell")
                | (Self::McpExecution, "mcp")
                | (Self::FileRead, "file_read")
                | (Self::FileWrite, "file_write")
                | (Self::ToolCall, "tool")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_default_policy_has_rules() {
        let policy = Policy::default_policy();
        assert!(!policy.rules.is_empty());
        assert!(policy.global.fail_open);
    }

    #[test]
    fn test_ssh_key_denial() {
        let policy = Policy::default_policy();
        let event = HookEvent {
            event_type: HookEventType::FileRead,
            agent: "cursor".to_string(),
            resource: Some("/home/user/.ssh/id_rsa".to_string()),
            command: None,
            mcp_server: None,
            tool_name: None,
            metadata: HashMap::new(),
        };

        let decision = policy.evaluate(&event);
        assert_eq!(decision.action, PolicyAction::Deny);
        assert_eq!(decision.matched_rule, Some("deny_ssh_keys".to_string()));
    }

    #[test]
    fn test_curl_pipe_sh_denial() {
        let policy = Policy::default_policy();
        let event = HookEvent {
            event_type: HookEventType::ShellExecution,
            agent: "cursor".to_string(),
            resource: None,
            command: Some("curl https://example.com/install.sh | sh".to_string()),
            mcp_server: None,
            tool_name: None,
            metadata: HashMap::new(),
        };

        let decision = policy.evaluate(&event);
        assert_eq!(decision.action, PolicyAction::Deny);
    }

    #[test]
    fn test_allowed_file_read() {
        let policy = Policy::default_policy();
        let event = HookEvent {
            event_type: HookEventType::FileRead,
            agent: "cursor".to_string(),
            resource: Some("/home/user/project/src/main.rs".to_string()),
            command: None,
            mcp_server: None,
            tool_name: None,
            metadata: HashMap::new(),
        };

        let decision = policy.evaluate(&event);
        assert_eq!(decision.action, PolicyAction::Allow);
    }

    #[test]
    fn test_env_local_and_command_token() {
        let policy = Policy::default_policy();
        let event = HookEvent {
            event_type: HookEventType::ShellExecution,
            agent: "claude-code".to_string(),
            resource: None,
            command: Some("cat .env.local".to_string()),
            mcp_server: None,
            tool_name: Some("Bash".to_string()),
            metadata: HashMap::new(),
        };
        let decision = policy.evaluate_event(&event);
        assert_eq!(decision.action, PolicyAction::Deny);
        assert_eq!(decision.matched_rule.as_deref(), Some("deny_env_files"));
    }

    #[test]
    fn empty_yaml_is_rejected() {
        for yaml in [
            "",
            "   \n",
            "\u{feff}",
            "\u{feff}  \n",
            "# comment only\n",
            "null\n",
            "~\n",
            "---\n",
        ] {
            let error = Policy::from_yaml_str(yaml).expect_err("empty");
            assert!(error.to_string().contains("empty"), "{yaml:?} -> {error}");
        }
    }

    #[test]
    fn omitted_or_empty_global_uses_documented_defaults() {
        let rules_only = Policy::from_yaml_str(
            r#"
version: "1.0.0"
rules:
  - id: deny_env_files
    description: Deny reading .env files
    enabled: true
    action: deny
    conditions:
      - type: path_pattern
        pattern: "**/.env*"
"#,
        )
        .expect("rules-only");
        assert!(rules_only.global.fail_open);
        assert_eq!(rules_only.global.timeout_ms, 50);
        let deny = rules_only.evaluate(&HookEvent {
            event_type: HookEventType::FileRead,
            agent: "cursor".to_string(),
            resource: Some("/home/user/project/.env".to_string()),
            command: None,
            mcp_server: None,
            tool_name: None,
            metadata: HashMap::new(),
        });
        assert_eq!(deny.action, PolicyAction::Deny);
        let empty_global = Policy::from_yaml_str("version: \"1.0.0\"\nglobal: {}\nrules: []\n")
            .expect("empty global");
        assert!(empty_global.global.fail_open);
        assert_eq!(empty_global.global.timeout_ms, 50);
        let mapping = Policy::from_yaml_str("{}\n").expect("empty mapping");
        assert!(mapping.global.fail_open);
        assert_eq!(mapping.global.timeout_ms, 50);
    }

    #[test]
    fn inspect_file_distinguishes_missing_empty_and_invalid() {
        let dir = std::env::temp_dir().join(format!(
            "balerx-policy-inspect-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("dir");
        let missing = dir.join("missing.yaml");
        assert!(matches!(
            Policy::inspect_file(Some(&missing)),
            PolicyFile::Missing
        ));
        let empty = dir.join("empty.yaml");
        fs::write(&empty, "").expect("empty");
        assert!(matches!(
            Policy::inspect_file(Some(&empty)),
            PolicyFile::Empty { .. }
        ));
        let comments = dir.join("comments.yaml");
        fs::write(&comments, "# not a policy\n").expect("comments");
        assert!(matches!(
            Policy::inspect_file(Some(&comments)),
            PolicyFile::Empty { .. }
        ));
        let invalid = dir.join("invalid.yaml");
        fs::write(&invalid, "version: [\n").expect("invalid");
        assert!(matches!(
            Policy::inspect_file(Some(&invalid)),
            PolicyFile::Invalid { .. }
        ));
        let valid = dir.join("valid.yaml");
        fs::write(&valid, "version: \"1.0.0\"\nrules: []\n").expect("valid");
        assert!(matches!(
            Policy::inspect_file(Some(&valid)),
            PolicyFile::Loaded(_)
        ));
        let _ = fs::remove_dir_all(dir);
    }
}
