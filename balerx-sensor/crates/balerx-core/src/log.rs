use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub timestamp: String,
    pub event_id: String,
    pub event_type: String,
    pub agent: String,
    pub action: String,
    pub resource: Option<String>,
    pub decision: Option<String>,
    pub metadata: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_args: Option<serde_json::Value>,
}

#[derive(Debug)]
pub struct ActivityLog {
    log_path: PathBuf,
    metadata_only: bool,
}

impl ActivityLog {
    pub fn new(log_path: impl Into<PathBuf>, metadata_only: bool) -> Self {
        Self {
            log_path: log_path.into(),
            metadata_only,
        }
    }

    #[must_use]
    pub fn default_log() -> Self {
        let log_dir = crate::canary::data_root().join("logs");

        let log_path = log_dir.join("activity.jsonl");

        Self {
            log_path,
            metadata_only: true,
        }
    }

    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.log_path
    }

    /// Appends an event to the activity log.
    ///
    /// # Errors
    ///
    /// Returns an error if the log file cannot be created, opened, or written to.
    pub fn append(&self, mut event: ActivityEvent) -> Result<()> {
        if self.metadata_only {
            event.tool_args = None;
        }

        if let Some(parent) = self.log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .with_context(|| format!("Failed to open log file: {}", self.log_path.display()))?;

        let mut writer = BufWriter::new(file);
        let line = serde_json::to_string(&event).context("Failed to serialize activity event")?;

        writeln!(writer, "{line}").context("Failed to write to log file")?;

        writer.flush().context("Failed to flush log file")?;

        Ok(())
    }

    /// Reads the most recent events from the log.
    ///
    /// # Errors
    ///
    /// Returns an error if the log file cannot be read.
    pub fn read_recent(&self, limit: usize) -> Result<Vec<ActivityEvent>> {
        if !self.log_path.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(&self.log_path)?;
        let mut events: Vec<ActivityEvent> = content
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        events.reverse();
        events.truncate(limit);
        events.reverse();

        Ok(events)
    }

    /// Filters events by agent and/or event type.
    ///
    /// # Errors
    ///
    /// Returns an error if the log file cannot be read.
    pub fn filter(
        &self,
        agent: Option<&str>,
        event_type: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ActivityEvent>> {
        if !self.log_path.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(&self.log_path)?;
        let events: Vec<ActivityEvent> = content
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .filter(|event: &ActivityEvent| {
                let agent_match = agent.map_or(true, |a| event.agent == a);
                let type_match = event_type.map_or(true, |t| event.event_type == t);
                agent_match && type_match
            })
            .take(limit)
            .collect();

        Ok(events)
    }
}

impl ActivityEvent {
    #[must_use]
    pub fn new(
        event_type: impl Into<String>,
        agent: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: event_type.into(),
            agent: agent.into(),
            action: action.into(),
            resource: None,
            decision: None,
            metadata: serde_json::json!({}),
            tool_args: None,
        }
    }

    #[must_use]
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    #[must_use]
    pub fn with_decision(mut self, decision: impl Into<String>) -> Self {
        self.decision = Some(decision.into());
        self
    }

    #[must_use]
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }

    #[must_use]
    pub fn with_tool_args(mut self, args: serde_json::Value) -> Self {
        self.tool_args = Some(args);
        self
    }
}

/// Redact sensitive values from tool arguments
pub fn redact_secrets(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let key_lower = key.to_lowercase();
                if key_lower.contains("password")
                    || key_lower.contains("secret")
                    || key_lower.contains("token")
                    || key_lower.contains("key")
                    || key_lower.contains("auth")
                {
                    *val = serde_json::Value::String("[REDACTED]".to_string());
                } else {
                    redact_secrets(val);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                redact_secrets(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activity_event_creation() {
        let event = ActivityEvent::new("tool_call", "cursor", "file_read")
            .with_resource("/path/to/file")
            .with_decision("allow");

        assert_eq!(event.event_type, "tool_call");
        assert_eq!(event.agent, "cursor");
        assert_eq!(event.resource, Some("/path/to/file".to_string()));
    }

    #[test]
    fn test_secret_redaction() {
        let mut value = serde_json::json!({
            "username": "alice",
            "password": "secret123",
            "api_key": "sk-1234",
            "data": {
                "token": "abc",
                "value": "safe"
            }
        });

        redact_secrets(&mut value);

        assert_eq!(value["username"], "alice");
        assert_eq!(value["password"], "[REDACTED]");
        assert_eq!(value["api_key"], "[REDACTED]");
        assert_eq!(value["data"]["token"], "[REDACTED]");
        assert_eq!(value["data"]["value"], "safe");
    }

    #[test]
    fn test_log_serialization() {
        let event = ActivityEvent::new("test", "cursor", "action");
        let json = serde_json::to_string(&event).unwrap();
        let parsed: ActivityEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.event_type, parsed.event_type);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_default_log_uses_local_appdata() {
        let log = ActivityLog::default_log();
        let log_path = &log.log_path;

        if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") {
            let expected_prefix = std::path::PathBuf::from(local_appdata);
            assert!(
                log_path.starts_with(&expected_prefix),
                "Log path {log_path:?} should start with %LOCALAPPDATA% {expected_prefix:?}"
            );
        }

        assert!(log_path.to_string_lossy().contains("balerx"));
        assert!(log_path.to_string_lossy().contains("logs"));
        assert!(log_path.to_string_lossy().ends_with("activity.jsonl"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_macos_default_log_uses_app_support() {
        let log = ActivityLog::default_log();
        let log_path = &log.log_path;

        let expected_segment = "Library/Application Support";
        assert!(
            log_path.to_string_lossy().contains(expected_segment),
            "Log path {log_path:?} should contain '{expected_segment}'"
        );

        assert!(log_path.to_string_lossy().contains("balerx"));
        assert!(log_path.to_string_lossy().contains("logs"));
        assert!(log_path.to_string_lossy().ends_with("activity.jsonl"));
    }
}
