use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct HookInstaller {
    backup_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    pub agent_type: AgentType,
    pub config_path: PathBuf,
    pub hooks: Vec<Hook>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    ClaudeCode,
    Cursor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hook {
    pub name: String,
    pub command: String,
    pub enabled: bool,
}

impl HookInstaller {
    #[must_use]
    pub fn new() -> Self {
        let backup_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("balerx")
            .join("backups");

        Self { backup_dir }
    }

    /// Installs guard hooks for the specified agent type.
    ///
    /// # Errors
    ///
    /// Returns an error if hook configuration files cannot be read, written, or backed up.
    pub fn install(&self, agent_type: AgentType) -> Result<()> {
        match agent_type {
            AgentType::ClaudeCode => self.install_claude_code_hooks(),
            AgentType::Cursor => self.install_cursor_hooks(),
        }
    }

    /// Uninstalls guard hooks for the specified agent type.
    ///
    /// # Errors
    ///
    /// Returns an error if hook configuration files cannot be read, written, or restored.
    pub fn uninstall(&self, agent_type: AgentType) -> Result<()> {
        match agent_type {
            AgentType::ClaudeCode => self.uninstall_claude_code_hooks(),
            AgentType::Cursor => self.uninstall_cursor_hooks(),
        }
    }

    fn install_claude_code_hooks(&self) -> Result<()> {
        let config_path = Self::claude_code_config_path()?;

        if config_path.exists() {
            self.backup_config(&config_path, "claude-code")?;
        }

        let mut config: serde_json::Value = if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            serde_json::from_str(&content)?
        } else {
            serde_json::json!({})
        };

        if config.get("hooks").is_none() {
            config["hooks"] = serde_json::json!({});
        }

        let hooks = config["hooks"]
            .as_object_mut()
            .context("hooks field is not an object")?;

        hooks.insert(
            "PreToolUse".to_string(),
            serde_json::json!({
                "command": Self::hook_command(),
                "args": ["hook", "--event-type", "pre_tool_use"],
            }),
        );

        hooks.insert(
            "PostToolUse".to_string(),
            serde_json::json!({
                "command": Self::hook_command(),
                "args": ["hook", "--event-type", "post_tool_use"],
            }),
        );

        fs::create_dir_all(config_path.parent().unwrap())?;
        fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;

        Ok(())
    }

    fn install_cursor_hooks(&self) -> Result<()> {
        let config_path = Self::cursor_hooks_config_path()?;

        if config_path.exists() {
            self.backup_config(&config_path, "cursor")?;
        }

        let hooks_config = serde_json::json!({
            "beforeShellExecution": {
                "command": Self::hook_command(),
                "args": ["hook", "--event-type", "before_shell_execution"]
            },
            "beforeMCPExecution": {
                "command": Self::hook_command(),
                "args": ["hook", "--event-type", "before_mcp_execution"]
            }
        });

        fs::create_dir_all(config_path.parent().unwrap())?;
        fs::write(&config_path, serde_json::to_string_pretty(&hooks_config)?)?;

        Ok(())
    }

    fn uninstall_claude_code_hooks(&self) -> Result<()> {
        let config_path = Self::claude_code_config_path()?;
        let backup_path = self.backup_dir.join("claude-code").join("config.json");

        if backup_path.exists() {
            fs::copy(&backup_path, &config_path)?;
            println!("Restored Claude Code config from backup");
        } else if config_path.exists() {
            let mut config: serde_json::Value = {
                let content = fs::read_to_string(&config_path)?;
                serde_json::from_str(&content)?
            };

            if let Some(hooks) = config.get_mut("hooks").and_then(|h| h.as_object_mut()) {
                hooks.remove("PreToolUse");
                hooks.remove("PostToolUse");

                fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;
            }
        }

        Ok(())
    }

    fn uninstall_cursor_hooks(&self) -> Result<()> {
        let config_path = Self::cursor_hooks_config_path()?;
        let backup_path = self.backup_dir.join("cursor").join("hooks.json");

        if backup_path.exists() {
            fs::copy(&backup_path, &config_path)?;
            println!("Restored Cursor hooks config from backup");
        } else if config_path.exists() {
            fs::remove_file(&config_path)?;
        }

        Ok(())
    }

    fn backup_config(&self, config_path: &Path, agent_name: &str) -> Result<()> {
        let backup_dir = self.backup_dir.join(agent_name);
        fs::create_dir_all(&backup_dir)?;

        let backup_path = backup_dir.join(config_path.file_name().context("Invalid config path")?);

        fs::copy(config_path, &backup_path)?;
        println!("Backed up existing config to: {}", backup_path.display());

        Ok(())
    }

    fn claude_code_config_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Could not determine home directory")?;
        Ok(home.join(".claude.json"))
    }

    fn cursor_hooks_config_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Could not determine home directory")?;
        Ok(home.join(".cursor").join("hooks.json"))
    }

    #[must_use]
    fn hook_command() -> String {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_else(|| "balerx".to_string())
    }
}

impl Default for HookInstaller {
    fn default() -> Self {
        Self::new()
    }
}

/// Reference: Claude Code hooks documentation
/// <https://code.claude.com/docs/en/hooks>
/// Hooks receive JSON on stdin and must return JSON on stdout with:
/// - `PreToolUse`: { "allow": bool, "reason": string }
/// - `PostToolUse`: (logging only, no decision)
///
/// Reference: Cursor hooks documentation
/// <https://cursor.com/docs/hooks>
/// Hooks receive JSON on stdin and must return JSON on stdout with:
/// - { "allow": bool, "reason": string } for before* hooks
/// - `beforeShellExecution`: { "command": string, "cwd": string, ... }
/// - `beforeMCPExecution`: { "server": string, "tool": string, "args": object, ... }
///
/// Note: Hook input/output formats are based on publicly available documentation
/// as of 2026-10-20. These formats may change as the products evolve.
/// Verified against:
/// - Claude Code v0.x hooks API
/// - Cursor v0.x hooks API
///
/// Known uncertainties:
/// - Exact error handling behavior when hook process fails
/// - Whether hooks can modify tool arguments (assumed no for safety)
/// - Timeout behavior (we target <50ms p95)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_installer_creation() {
        let installer = HookInstaller::new();
        assert!(installer.backup_dir.to_string_lossy().contains("balerx"));
    }

    #[test]
    fn test_agent_type_serialization() {
        let agent = AgentType::ClaudeCode;
        let json = serde_json::to_string(&agent).unwrap();
        assert_eq!(json, "\"claude_code\"");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_claude_code_config_path() {
        let path = HookInstaller::claude_code_config_path();
        assert!(path.is_ok());
        let path = path.unwrap();

        assert!(path.to_string_lossy().contains(".claude.json"));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_cursor_hooks_config_path() {
        let path = HookInstaller::cursor_hooks_config_path();
        assert!(path.is_ok());
        let path = path.unwrap();

        assert!(path.to_string_lossy().contains(".cursor"));
        assert!(path.to_string_lossy().contains("hooks.json"));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_backup_dir_uses_local_appdata() {
        let installer = HookInstaller::new();
        let backup_dir = &installer.backup_dir;

        if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") {
            let expected_prefix = std::path::PathBuf::from(local_appdata);
            assert!(
                backup_dir.starts_with(&expected_prefix),
                "Backup dir {backup_dir:?} should start with %LOCALAPPDATA% {expected_prefix:?}"
            );
        }

        assert!(backup_dir.to_string_lossy().contains("balerx"));
        assert!(backup_dir.to_string_lossy().contains("backups"));
    }
}
