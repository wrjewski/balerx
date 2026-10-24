use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct HookInstaller {
    home: PathBuf,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardStatus {
    pub claude_user: bool,
    pub claude_project: bool,
    pub cursor_user: bool,
    pub claude_settings: PathBuf,
    pub cursor_hooks: PathBuf,
}

impl HookInstaller {
    #[must_use]
    pub fn new() -> Self {
        Self {
            home: crate::agent::home_dir().unwrap_or_default(),
        }
    }

    #[must_use]
    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        Self { home: home.into() }
    }

    /// Installs guard hooks for the specified agent type.
    ///
    /// Claude Code hooks are merged into `~/.claude/settings.json`. When a
    /// project `.claude/settings.json` already exists and is a different file,
    /// the same entries are merged there. One file is written once, including
    /// when Windows reports it with a `\\?\` prefix. Cursor hooks are merged
    /// into `~/.cursor/hooks.json`. Existing hooks are kept.
    ///
    /// # Errors
    ///
    /// Returns an error if a hook configuration file cannot be read or written.
    pub fn install(&self, agent_type: AgentType) -> Result<Vec<PathBuf>> {
        self.ensure_absolute_home()?;
        match agent_type {
            AgentType::ClaudeCode => {
                let cwd =
                    std::env::current_dir().context("The working directory is not available")?;
                self.install_claude_from(&cwd)
            }
            AgentType::Cursor => self.install_cursor_hooks(),
        }
    }

    /// Removes only Balerx hook entries. Other hooks and later edits stay.
    ///
    /// # Errors
    ///
    /// Returns an error if a hook configuration file cannot be read or written.
    pub fn uninstall(&self, agent_type: AgentType) -> Result<Vec<PathBuf>> {
        self.ensure_absolute_home()?;
        match agent_type {
            AgentType::ClaudeCode => {
                let cwd =
                    std::env::current_dir().context("The working directory is not available")?;
                self.uninstall_claude_from(&cwd)
            }
            AgentType::Cursor => self.uninstall_cursor_hooks(),
        }
    }

    fn ensure_absolute_home(&self) -> Result<()> {
        if self.home.is_absolute() {
            Ok(())
        } else {
            anyhow::bail!(crate::agent::HOME_REQUIRED)
        }
    }

    #[must_use]
    pub fn status(&self) -> GuardStatus {
        let claude_settings = self.home.join(".claude").join("settings.json");
        let cursor_hooks = self.home.join(".cursor").join("hooks.json");
        let project = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".claude")
            .join("settings.json");
        GuardStatus {
            claude_user: file_contains_balerx_hook(&claude_settings),
            claude_project: file_contains_balerx_hook(&project),
            cursor_user: file_contains_balerx_hook(&cursor_hooks),
            claude_settings,
            cursor_hooks,
        }
    }

    fn install_claude_from(&self, cwd: &Path) -> Result<Vec<PathBuf>> {
        let targets = claude_settings_paths(&self.home, cwd, false);
        for path in &targets {
            merge_claude_file(path)?;
        }
        Ok(targets)
    }

    fn install_cursor_hooks(&self) -> Result<Vec<PathBuf>> {
        let path = self.home.join(".cursor").join("hooks.json");
        merge_cursor_file(&path)?;
        Ok(vec![path])
    }

    fn uninstall_claude_from(&self, cwd: &Path) -> Result<Vec<PathBuf>> {
        let targets = claude_settings_paths(&self.home, cwd, true);
        for path in &targets {
            strip_claude_file(path)?;
        }
        Ok(targets)
    }

    fn uninstall_cursor_hooks(&self) -> Result<Vec<PathBuf>> {
        let path = self.home.join(".cursor").join("hooks.json");
        if path.is_file() {
            strip_cursor_file(&path)?;
            return Ok(vec![path]);
        }
        Ok(Vec::new())
    }
}

impl Default for HookInstaller {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn hook_command() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.to_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "balerx".to_string())
}

#[must_use]
pub fn balerx_hook_command(event_type: &str) -> String {
    format!("{} hook --event-type {event_type}", hook_command())
}

/// A Balerx hook command contains `balerx` and `hook`, and it invokes the
/// `balerx` or `balerx.exe` binary with a separate `hook` argument.
/// `my-balerx-webhook.sh` does not match.
#[must_use]
pub fn is_balerx_hook_command(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    if !(lower.contains("balerx") && lower.contains("hook")) {
        return false;
    }
    let tokens = command_tokens(command);
    let has_hook = tokens
        .iter()
        .any(|token| token.eq_ignore_ascii_case("hook"));
    let has_binary = tokens.iter().any(|token| is_balerx_binary_token(token));
    has_hook && has_binary
}

fn command_tokens(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for ch in command.chars() {
        match quote {
            Some(mark) if ch == mark => quote = None,
            None if ch == '"' || ch == '\'' => quote = Some(ch),
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            Some(_) | None => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn is_balerx_binary_token(token: &str) -> bool {
    let name = token.rsplit(['/', '\\']).next().unwrap_or(token);
    if name.eq_ignore_ascii_case("balerx") || name.eq_ignore_ascii_case("balerx.exe") {
        return true;
    }
    // `guard install` records the running executable. Tests run a harness whose
    // file name is not `balerx`, so that exact path counts too.
    std::env::current_exe().is_ok_and(|current| {
        token == current.to_string_lossy()
            || Some(std::ffi::OsStr::new(name)) == current.file_name()
    })
}

/// True when `text` is a Balerx hook command or contains one inside quotes.
/// Settings files store the command in a JSON string.
#[must_use]
pub fn text_contains_balerx_hook(text: &str) -> bool {
    if is_balerx_hook_command(text) {
        return true;
    }
    let mut current = String::new();
    let mut quote = None;
    for ch in text.chars() {
        match quote {
            Some(mark) if ch == mark => {
                if is_balerx_hook_command(&current) {
                    return true;
                }
                current.clear();
                quote = None;
            }
            Some(_) => current.push(ch),
            None if ch == '"' || ch == '\'' => {
                quote = Some(ch);
                current.clear();
            }
            None => {}
        }
    }
    false
}

/// Merges Balerx entries into a Claude Code settings file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or written.
pub fn merge_claude_file(path: &Path) -> Result<()> {
    let mut config = read_json_or_empty(path)?;
    if !config.is_object() {
        config = serde_json::json!({});
    }
    if !config.get("hooks").is_some_and(Value::is_object) {
        config["hooks"] = serde_json::json!({});
    }
    ensure_claude_event(&mut config["hooks"]["PreToolUse"], "pre_tool_use");
    ensure_claude_event(&mut config["hooks"]["PostToolUse"], "post_tool_use");
    write_json(path, &config)
}

/// Merges Balerx entries into a Cursor hooks file, keeping `version` and other hooks.
///
/// # Errors
///
/// Returns an error if the file cannot be read or written.
pub fn merge_cursor_file(path: &Path) -> Result<()> {
    let mut config = read_json_or_empty(path)?;
    if !config.is_object() {
        config = serde_json::json!({});
    }
    if config.get("version").is_none() {
        config["version"] = serde_json::json!(1);
    }
    if !config.get("hooks").is_some_and(Value::is_object) {
        config["hooks"] = serde_json::json!({});
    }
    for event in [
        "beforeShellExecution",
        "beforeMCPExecution",
        "beforeReadFile",
        "afterFileEdit",
        "afterShellExecution",
    ] {
        if config.get(event).is_some() && config["hooks"].get(event).is_none() {
            let moved = config.as_object_mut().and_then(|map| map.remove(event));
            if let Some(moved) = moved {
                config["hooks"][event] = cursor_event_array(moved);
            }
        }
    }
    ensure_cursor_event(
        &mut config["hooks"]["beforeShellExecution"],
        "before_shell_execution",
    );
    ensure_cursor_event(
        &mut config["hooks"]["beforeMCPExecution"],
        "before_mcp_execution",
    );
    ensure_cursor_event(&mut config["hooks"]["beforeReadFile"], "before_read_file");
    write_json(path, &config)
}

/// Removes Balerx command hooks from a Claude Code settings file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or written.
pub fn strip_claude_file(path: &Path) -> Result<()> {
    let mut config = read_json_or_empty(path)?;
    if let Some(hooks) = config.get_mut("hooks").and_then(Value::as_object_mut) {
        for key in ["PreToolUse", "PostToolUse", "PermissionRequest"] {
            if let Some(slot) = hooks.get_mut(key) {
                strip_claude_slot(slot);
            }
        }
    }
    prune_empty_hooks(&mut config);
    write_json(path, &config)
}

/// Removes Balerx command hooks from a Cursor hooks file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or written.
pub fn strip_cursor_file(path: &Path) -> Result<()> {
    let mut config = read_json_or_empty(path)?;
    if let Some(hooks) = config.get_mut("hooks").and_then(Value::as_object_mut) {
        let keys: Vec<String> = hooks.keys().cloned().collect();
        for key in keys {
            if let Some(slot) = hooks.get_mut(&key) {
                strip_cursor_slot(slot);
            }
        }
    }
    if let Some(map) = config.as_object_mut() {
        let keys: Vec<String> = map.keys().cloned().collect();
        for key in keys {
            if key == "version" || key == "hooks" {
                continue;
            }
            if let Some(slot) = map.get_mut(&key) {
                strip_cursor_slot(slot);
            }
        }
    }
    prune_empty_hooks(&mut config);
    write_json(path, &config)
}

fn prune_empty_hooks(config: &mut Value) {
    let Some(map) = config.as_object_mut() else {
        return;
    };
    if let Some(Value::Object(hooks)) = map.get_mut("hooks") {
        hooks.retain(|_, value| !hook_value_is_empty(value));
    }
    if map
        .get("hooks")
        .and_then(Value::as_object)
        .is_some_and(Map::is_empty)
    {
        map.remove("hooks");
    }
    let stale: Vec<String> = map
        .iter()
        .filter(|(key, value)| *key != "version" && *key != "hooks" && hook_value_is_empty(value))
        .map(|(key, _)| (*key).clone())
        .collect();
    for key in stale {
        map.remove(&key);
    }
}

fn hook_value_is_empty(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
        Value::Null => true,
        Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

fn ensure_claude_event(slot: &mut Value, event_type: &str) {
    normalize_claude_slot(slot);
    let Some(groups) = slot.as_array_mut() else {
        return;
    };
    let present = groups.iter().any(|group| {
        group
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|hooks| {
                hooks.iter().any(|hook| {
                    hook.get("command")
                        .and_then(Value::as_str)
                        .is_some_and(is_balerx_hook_command)
                })
            })
    });
    if present {
        return;
    }
    groups.push(serde_json::json!({
        "matcher": "*",
        "hooks": [{
            "type": "command",
            "command": balerx_hook_command(event_type)
        }]
    }));
}

fn normalize_claude_slot(slot: &mut Value) {
    if slot.is_array() {
        return;
    }
    if let Some(command) = slot.get("command").and_then(Value::as_str) {
        if is_balerx_hook_command(command) {
            *slot = serde_json::json!([]);
            return;
        }
        let preserved = slot.clone();
        *slot = serde_json::json!([{
            "matcher": "*",
            "hooks": [preserved]
        }]);
        return;
    }
    *slot = serde_json::json!([]);
}

fn strip_claude_slot(slot: &mut Value) {
    let Some(groups) = slot.as_array_mut() else {
        return;
    };
    for group in groups.iter_mut() {
        if let Some(hooks) = group.get_mut("hooks").and_then(Value::as_array_mut) {
            hooks.retain(|hook| {
                !hook
                    .get("command")
                    .and_then(Value::as_str)
                    .is_some_and(is_balerx_hook_command)
            });
        }
    }
    groups.retain(|group| match group.get("hooks").and_then(Value::as_array) {
        Some(hooks) => !hooks.is_empty(),
        None => true,
    });
}

fn ensure_cursor_event(slot: &mut Value, event_type: &str) {
    if !slot.is_array() {
        *slot = cursor_event_array(std::mem::take(slot));
    }
    let Some(hooks) = slot.as_array_mut() else {
        return;
    };
    let present = hooks.iter().any(|hook| {
        hook.get("command")
            .and_then(Value::as_str)
            .is_some_and(is_balerx_hook_command)
    });
    if !present {
        hooks.push(serde_json::json!({
            "command": balerx_hook_command(event_type)
        }));
    }
}

fn cursor_event_array(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items),
        Value::Object(map) => Value::Array(vec![Value::Object(map)]),
        Value::Null => serde_json::json!([]),
        other => Value::Array(vec![other]),
    }
}

fn strip_cursor_slot(slot: &mut Value) {
    match slot {
        Value::Array(items) => {
            items.retain(|hook| {
                !hook
                    .get("command")
                    .and_then(Value::as_str)
                    .is_some_and(is_balerx_hook_command)
            });
        }
        Value::Object(map)
            if map
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(is_balerx_hook_command) =>
        {
            map.clear();
        }
        Value::Object(_) | Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn file_contains_balerx_hook(path: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|text| text_contains_balerx_hook(&text))
}

fn read_json_or_empty(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(serde_json::json!({}));
    }
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    if content.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_str(&content).with_context(|| format!("Failed to parse {}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(value)?;
    fs::write(path, text).with_context(|| format!("Failed to write {}", path.display()))
}

/// User settings, plus a project settings file when that file already exists.
/// The same path is listed once. `user_must_exist` skips a missing user file
/// during uninstall.
fn claude_settings_paths(home: &Path, cwd: &Path, user_must_exist: bool) -> Vec<PathBuf> {
    let mut targets = Vec::new();
    let user = home.join(".claude").join("settings.json");
    if !user_must_exist || user.is_file() {
        push_unique(&mut targets, user);
    }
    let project = cwd.join(".claude").join("settings.json");
    if project.is_file() {
        push_unique(&mut targets, project);
    }
    targets
}

fn push_unique(paths: &mut Vec<PathBuf>, path: PathBuf) {
    let key = path_identity(&path);
    if paths.iter().any(|existing| path_identity(existing) == key) {
        return;
    }
    paths.push(path);
}

/// Identity used to compare hook files. Strips the Windows `\\?\` prefix,
/// including `\\?\UNC\`, and compares Windows paths case-insensitively.
fn path_identity(path: &Path) -> String {
    let candidate = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut text = strip_verbatim(&candidate.to_string_lossy());
    if looks_like_windows_path(&text) {
        text = text.replace('/', "\\");
        while text.ends_with('\\') && text.len() > 3 {
            text.pop();
        }
        text.make_ascii_lowercase();
    } else {
        while text.ends_with('/') && text.len() > 1 {
            text.pop();
        }
    }
    text
}

fn strip_verbatim(text: &str) -> String {
    const VERBATIM_UNC: &str = "\\\\?\\UNC\\";
    const VERBATIM: &str = "\\\\?\\";
    if let Some(rest) = text.strip_prefix(VERBATIM_UNC) {
        return format!("\\\\{rest}");
    }
    text.strip_prefix(VERBATIM)
        .map_or_else(|| text.to_string(), ToOwned::to_owned)
}

fn looks_like_windows_path(text: &str) -> bool {
    cfg!(windows) || text.contains('\\') || text.as_bytes().get(1) == Some(&b':')
}

#[allow(dead_code)]
fn object_keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .map(Map::keys)
        .map(|keys| keys.cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "balerx-guard-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temp home");
        path
    }

    #[test]
    fn claude_install_merges_documented_shape_and_keeps_other_settings() {
        let home = temp_home("claude");
        let settings = home.join(".claude").join("settings.json");
        fs::create_dir_all(settings.parent().expect("parent")).expect("dir");
        fs::write(
            &settings,
            r#"{"theme":"dark","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo keep"}]}]}}"#,
        )
        .expect("seed");

        merge_claude_file(&settings).expect("merge");
        let value: Value =
            serde_json::from_str(&fs::read_to_string(&settings).expect("read")).expect("json");
        assert_eq!(value["theme"], "dark");
        let groups = value["hooks"]["PreToolUse"].as_array().expect("array");
        assert!(groups.iter().any(|group| group["matcher"] == "Bash"));
        let ours = groups
            .iter()
            .find(|group| group["matcher"] == "*")
            .expect("balerx matcher");
        let command = ours["hooks"][0]["command"].as_str().expect("command");
        assert_eq!(ours["hooks"][0]["type"], "command");
        assert!(is_balerx_hook_command(command));
        assert!(command.contains("pre_tool_use"));
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn claude_uninstall_removes_only_balerx_entries() {
        let home = temp_home("claude-rm");
        let settings = home.join(".claude").join("settings.json");
        merge_claude_file(&settings).expect("install");
        let mut value: Value =
            serde_json::from_str(&fs::read_to_string(&settings).expect("read")).expect("json");
        value["hooks"]["PreToolUse"]
            .as_array_mut()
            .expect("array")
            .push(serde_json::json!({
                "matcher": "Edit",
                "hooks": [{"type": "command", "command": "echo user"}]
            }));
        fs::write(
            &settings,
            serde_json::to_string_pretty(&value).expect("json"),
        )
        .expect("write");
        let backup = home.join("backup-settings.json");
        fs::write(&backup, r#"{"hooks":{"PreToolUse":[]}}"#).expect("backup");

        strip_claude_file(&settings).expect("strip");
        let after: Value =
            serde_json::from_str(&fs::read_to_string(&settings).expect("read")).expect("json");
        let text = serde_json::to_string(&after).expect("text");
        assert!(!is_balerx_hook_command(&text));
        let groups = after["hooks"]["PreToolUse"].as_array().expect("kept array");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["hooks"][0]["command"], "echo user");
        assert_ne!(
            fs::read_to_string(&settings).expect("settings"),
            fs::read_to_string(&backup).expect("backup")
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn hook_command_requires_the_balerx_binary_and_a_hook_argument() {
        assert!(is_balerx_hook_command(
            "balerx hook --event-type pre_tool_use"
        ));
        assert!(is_balerx_hook_command(
            "/home/ada/.local/bin/balerx hook --event-type pre_tool_use"
        ));
        assert!(is_balerx_hook_command(
            r"C:\Users\Ada\AppData\Local\balerx\balerx.exe hook --event-type pre_tool_use"
        ));
        assert!(is_balerx_hook_command(
            r#""C:\Program Files\balerx\balerx.exe" hook --event-type pre_tool_use"#
        ));
        assert!(!is_balerx_hook_command("my-balerx-webhook.sh"));
        assert!(!is_balerx_hook_command("echo keep"));
        assert!(!is_balerx_hook_command("/usr/bin/balerx scan"));
    }

    #[test]
    fn uninstall_drops_empty_hook_lists_and_keeps_other_commands() {
        let home = temp_home("empty-hooks");
        let settings = home.join(".claude").join("settings.json");
        fs::create_dir_all(settings.parent().expect("parent")).expect("dir");
        fs::write(
            &settings,
            r#"{"theme":"dark","hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"balerx hook --event-type pre_tool_use"},{"type":"command","command":"my-balerx-webhook.sh"},{"type":"command","command":"echo keep"}]}],"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"balerx hook --event-type post_tool_use"}]}]}}"#,
        )
        .expect("seed");
        strip_claude_file(&settings).expect("strip");
        let value: Value =
            serde_json::from_str(&fs::read_to_string(&settings).expect("read")).expect("json");
        assert_eq!(value["theme"], "dark");
        assert!(value["hooks"].get("PostToolUse").is_none());
        let groups = value["hooks"]["PreToolUse"].as_array().expect("pre");
        assert_eq!(groups.len(), 1);
        let commands: Vec<&str> = groups[0]["hooks"]
            .as_array()
            .expect("hooks")
            .iter()
            .filter_map(|hook| hook["command"].as_str())
            .collect();
        assert_eq!(commands, ["my-balerx-webhook.sh", "echo keep"]);

        let cursor = home.join(".cursor").join("hooks.json");
        fs::create_dir_all(cursor.parent().expect("parent")).expect("dir");
        fs::write(
            &cursor,
            serde_json::json!({
                "version": 1,
                "hooks": {
                    "beforeShellExecution": [{"command": balerx_hook_command("before_shell_execution")}],
                    "beforeMCPExecution": [{"command": "my-balerx-webhook.sh"}]
                }
            })
            .to_string(),
        )
        .expect("cursor");
        strip_cursor_file(&cursor).expect("strip cursor");
        let cursor_value: Value =
            serde_json::from_str(&fs::read_to_string(&cursor).expect("read")).expect("json");
        assert_eq!(cursor_value["version"], 1);
        assert!(cursor_value["hooks"].get("beforeShellExecution").is_none());
        assert_eq!(
            cursor_value["hooks"]["beforeMCPExecution"][0]["command"],
            "my-balerx-webhook.sh"
        );

        fs::write(&settings, "{}").expect("reset");
        merge_claude_file(&settings).expect("install");
        strip_claude_file(&settings).expect("strip all");
        let empty: Value =
            serde_json::from_str(&fs::read_to_string(&settings).expect("read")).expect("json");
        assert!(empty.get("hooks").is_none());
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn cursor_install_keeps_version_and_existing_hooks() {
        let home = temp_home("cursor");
        let hooks = home.join(".cursor").join("hooks.json");
        fs::create_dir_all(hooks.parent().expect("parent")).expect("dir");
        fs::write(
            &hooks,
            r#"{"version":1,"hooks":{"afterFileEdit":[{"command":"./hooks/format.sh"}],"beforeShellExecution":[{"command":"./mine.sh"}]}}"#,
        )
        .expect("seed");

        merge_cursor_file(&hooks).expect("merge");
        let value: Value =
            serde_json::from_str(&fs::read_to_string(&hooks).expect("read")).expect("json");
        assert_eq!(value["version"], 1);
        assert_eq!(
            value["hooks"]["afterFileEdit"][0]["command"],
            "./hooks/format.sh"
        );
        let shell = value["hooks"]["beforeShellExecution"]
            .as_array()
            .expect("array");
        assert_eq!(shell[0]["command"], "./mine.sh");
        assert!(shell
            .iter()
            .any(|hook| hook["command"].as_str().is_some_and(is_balerx_hook_command)));
        assert!(value["hooks"]["beforeMCPExecution"].is_array());
        assert!(value["hooks"]["beforeReadFile"].is_array());

        merge_cursor_file(&hooks).expect("second merge");
        let again: Value =
            serde_json::from_str(&fs::read_to_string(&hooks).expect("read")).expect("json");
        let shell = again["hooks"]["beforeShellExecution"]
            .as_array()
            .expect("array");
        let ours = shell
            .iter()
            .filter(|hook| hook["command"].as_str().is_some_and(is_balerx_hook_command))
            .count();
        assert_eq!(ours, 1);
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn cursor_uninstall_does_not_restore_a_backup() {
        let home = temp_home("cursor-rm");
        let hooks = home.join(".cursor").join("hooks.json");
        fs::create_dir_all(hooks.parent().expect("parent")).expect("dir");
        fs::write(
            &hooks,
            serde_json::json!({
                "version": 1,
                "hooks": {
                    "afterFileEdit": [{"command": "./hooks/format.sh"}],
                    "beforeShellExecution": [
                        {"command": "./mine.sh"},
                        {"command": balerx_hook_command("before_shell_execution")}
                    ]
                }
            })
            .to_string(),
        )
        .expect("seed");
        let backup = home.join(".cursor").join("hooks.json.bak");
        fs::write(&backup, r#"{"version":1,"hooks":{}}"#).expect("backup");

        strip_cursor_file(&hooks).expect("strip");
        let value: Value =
            serde_json::from_str(&fs::read_to_string(&hooks).expect("read")).expect("json");
        assert_eq!(value["version"], 1);
        assert_eq!(
            value["hooks"]["afterFileEdit"][0]["command"],
            "./hooks/format.sh"
        );
        let shell = value["hooks"]["beforeShellExecution"]
            .as_array()
            .expect("shell");
        assert_eq!(shell.len(), 1);
        assert_eq!(shell[0]["command"], "./mine.sh");
        assert_eq!(
            fs::read_to_string(&backup).expect("backup"),
            r#"{"version":1,"hooks":{}}"#
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn agent_type_serialization() {
        let json = serde_json::to_string(&AgentType::ClaudeCode).expect("json");
        assert_eq!(json, "\"claude_code\"");
    }

    fn balerx_groups(slot: &Value) -> usize {
        slot.as_array().map_or(0, |groups| {
            groups
                .iter()
                .filter(|group| {
                    group
                        .get("hooks")
                        .and_then(Value::as_array)
                        .is_some_and(|hooks| {
                            hooks.iter().any(|hook| {
                                hook.get("command")
                                    .and_then(Value::as_str)
                                    .is_some_and(is_balerx_hook_command)
                            })
                        })
                })
                .count()
        })
    }

    #[test]
    fn verbatim_prefix_is_the_same_path() {
        let plain = PathBuf::from(r"C:\Users\Ada\.claude\settings.json");
        let prefixed = PathBuf::from(r"\\?\C:\Users\Ada\.claude\settings.json");
        let lower = PathBuf::from(r"\\?\c:\users\ada\.claude\settings.json");
        let slashes = PathBuf::from("C:/Users/Ada/.claude/settings.json");
        let unc = PathBuf::from(r"\\server\share\.claude\settings.json");
        let unc_prefixed = PathBuf::from(r"\\?\UNC\Server\Share\.claude\settings.json");
        assert_eq!(path_identity(&plain), path_identity(&prefixed));
        assert_eq!(path_identity(&plain), path_identity(&lower));
        assert_eq!(path_identity(&plain), path_identity(&slashes));
        assert_eq!(path_identity(&unc), path_identity(&unc_prefixed));

        let mut paths = Vec::new();
        push_unique(&mut paths, plain);
        push_unique(&mut paths, prefixed);
        push_unique(&mut paths, lower);
        push_unique(&mut paths, slashes);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    #[cfg(not(windows))]
    fn unix_path_identity_keeps_case() {
        let upper = PathBuf::from("/tmp/BalerxCase/.claude/settings.json");
        let lower = PathBuf::from("/tmp/balerxcase/.claude/settings.json");
        assert_ne!(path_identity(&upper), path_identity(&lower));
    }

    #[test]
    fn canonical_paths_collapse_before_a_second_write() {
        let home = temp_home("canon");
        let settings = home.join(".claude").join("settings.json");
        fs::create_dir_all(settings.parent().expect("parent")).expect("dir");
        fs::write(&settings, "{}\n").expect("seed");
        let via_dot = home.join(".").join(".claude").join("settings.json");
        let mut paths = Vec::new();
        push_unique(&mut paths, settings);
        push_unique(&mut paths, via_dot);
        assert_eq!(paths.len(), 1);
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn claude_install_lists_one_path_when_project_is_the_user_file() {
        let home = temp_home("claude-same");
        let settings = home.join(".claude").join("settings.json");
        fs::create_dir_all(settings.parent().expect("parent")).expect("dir");
        fs::write(&settings, "{}\n").expect("seed");
        let installer = HookInstaller::with_home(&home);

        let written = installer.install_claude_from(&home).expect("install");
        assert_eq!(written.len(), 1);
        assert_one_hook_each(&settings);

        let again = installer
            .install_claude_from(&home)
            .expect("second install");
        assert_eq!(again.len(), 1);
        assert_one_hook_each(&settings);

        let removed = installer.uninstall_claude_from(&home).expect("uninstall");
        assert_eq!(removed.len(), 1);
        let after = fs::read_to_string(&settings).expect("read");
        assert!(!is_balerx_hook_command(&after));
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn claude_install_writes_user_and_project_when_they_differ() {
        let home = temp_home("claude-user");
        let project = temp_home("claude-project");
        let project_settings = project.join(".claude").join("settings.json");
        fs::create_dir_all(project_settings.parent().expect("parent")).expect("dir");
        fs::write(&project_settings, "{}\n").expect("seed");
        let installer = HookInstaller::with_home(&home);

        let written = installer.install_claude_from(&project).expect("install");
        assert_eq!(written.len(), 2);
        let user_settings = home.join(".claude").join("settings.json");
        assert_one_hook_each(&user_settings);
        assert_one_hook_each(&project_settings);

        let again = installer
            .install_claude_from(&project)
            .expect("second install");
        assert_eq!(again.len(), 2);
        assert_one_hook_each(&user_settings);
        assert_one_hook_each(&project_settings);
        let _ = fs::remove_dir_all(home);
        let _ = fs::remove_dir_all(project);
    }

    fn assert_one_hook_each(path: &Path) {
        let value: Value =
            serde_json::from_str(&fs::read_to_string(path).expect("read")).expect("json");
        assert_eq!(balerx_groups(&value["hooks"]["PreToolUse"]), 1, "{path:?}");
        assert_eq!(balerx_groups(&value["hooks"]["PostToolUse"]), 1, "{path:?}");
        let pre = &value["hooks"]["PreToolUse"][0]["hooks"];
        let post = &value["hooks"]["PostToolUse"][0]["hooks"];
        assert_eq!(pre.as_array().expect("pre hooks").len(), 1);
        assert_eq!(post.as_array().expect("post hooks").len(), 1);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_cursor_hooks_live_under_user_profile() {
        let installer = HookInstaller::new();
        let status = installer.status();
        assert!(status.cursor_hooks.to_string_lossy().contains(".cursor"));
        assert!(status.cursor_hooks.to_string_lossy().contains("hooks.json"));
        assert!(status
            .claude_settings
            .to_string_lossy()
            .contains("settings.json"));
    }
}
