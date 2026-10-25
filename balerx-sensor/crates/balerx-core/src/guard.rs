use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

thread_local! {
    static HOOK_BINARY_OVERRIDE: RefCell<Option<String>> = const { RefCell::new(None) };
}

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
    if let Some(overridden) = HOOK_BINARY_OVERRIDE.with(|slot| slot.borrow().clone()) {
        return overridden;
    }
    std::env::current_exe()
        .ok()
        .and_then(|path| path.to_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "balerx".to_string())
}

/// Shell-quote a path for use in a hook command.
/// Windows-shaped paths (drive letter or UNC) use PowerShell quoting.
/// Other paths use POSIX single quotes. A POSIX path that contains a
/// backslash is not treated as a Windows path.
#[must_use]
pub fn shell_quote(path: &str) -> String {
    quote_path(path, is_windows_path_shape(path))
}

#[must_use]
pub fn quote_path(path: &str, windows: bool) -> String {
    if windows {
        powershell_quote(path)
    } else {
        posix_quote(path)
    }
}

fn posix_needs_quoting(path: &str) -> bool {
    path.is_empty()
        || path.chars().any(|ch| {
            matches!(
                ch,
                ' ' | '\t'
                    | '\n'
                    | '\''
                    | '"'
                    | '\\'
                    | '$'
                    | '`'
                    | '!'
                    | '*'
                    | '?'
                    | '['
                    | ']'
                    | '('
                    | ')'
                    | '{'
                    | '}'
                    | ';'
                    | '&'
                    | '|'
                    | '<'
                    | '>'
                    | '#'
                    | '~'
            )
        })
}

fn posix_quote(path: &str) -> String {
    if !posix_needs_quoting(path) {
        return path.to_string();
    }
    let mut result = String::from("'");
    for ch in path.chars() {
        if ch == '\'' {
            result.push_str("'\\''");
        } else {
            result.push(ch);
        }
    }
    result.push('\'');
    result
}

fn powershell_quote(path: &str) -> String {
    let escaped = path
        .replace('`', "``")
        .replace('$', "`$")
        .replace('"', "\"\"");
    format!("\"{escaped}\"")
}

/// Builds the hook command for the running binary on this OS.
#[must_use]
pub fn balerx_hook_command(event_type: &str) -> String {
    format_hook_command(&hook_command(), event_type, cfg!(windows))
}

/// Builds a hook command for `binary`. When `windows` is true the command
/// is always `& "path"` so PowerShell can invoke it.
#[must_use]
pub fn format_hook_command(binary: &str, event_type: &str, windows: bool) -> String {
    let quoted = quote_path(binary, windows);
    if windows {
        format!("& {quoted} hook --event-type {event_type}")
    } else if quoted != binary {
        format!("{quoted} hook --event-type {event_type}")
    } else {
        format!("{binary} hook --event-type {event_type}")
    }
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
    let mut chars = command.chars().peekable();
    let mut quote = None;

    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some('"'), '"') if chars.peek() == Some(&'"') => {
                chars.next();
                current.push('"');
            }
            (Some('\''), '\'') if chars.peek() == Some(&'\\') => {
                chars.next();
                if chars.peek() == Some(&'\'') {
                    chars.next();
                    if chars.peek() == Some(&'\'') {
                        chars.next();
                        current.push('\'');
                    }
                }
            }
            (Some('"'), '"') | (Some('\''), '\'') => quote = None,
            (None, '"') => quote = Some('"'),
            (None, '\'') => quote = Some('\''),
            (None, _) if ch.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
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
    if cfg!(windows) || is_windows_path_shape(&text) {
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

fn is_windows_path_shape(text: &str) -> bool {
    let stripped = strip_verbatim(text);
    let bytes = stripped.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return true;
    }
    stripped.starts_with("\\\\")
}

/// Path of the hook binary inside a stored hook command, if one is present.
#[must_use]
pub fn hook_binary_path_from_command(command: &str) -> Option<String> {
    command_tokens(command)
        .into_iter()
        .find(|token| token != "&" && is_balerx_binary_token(token))
        .map(|token| {
            if is_powershell_call_form(command) {
                unescape_powershell_escapes(&token)
            } else {
                token
            }
        })
}

fn is_powershell_call_form(command: &str) -> bool {
    command.trim_start().starts_with('&')
}

fn unescape_powershell_escapes(token: &str) -> String {
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '`' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Checks that a stored hook binary exists and is executable.
///
/// # Errors
///
/// Returns a user-facing message when the file is missing or not executable.
pub fn check_hook_binary(path: &str) -> Result<(), String> {
    let file = Path::new(path);
    if !path.contains('/') && !path.contains('\\') && !is_windows_path_shape(path) {
        if which_on_path(path) {
            return Ok(());
        }
        return Err(format!(
            "Guard hook binary is missing or not executable: {path}"
        ));
    }
    if !file.exists() {
        return Err(format!("Guard hook binary is missing: {path}"));
    }
    if !is_executable_file(file) {
        return Err(format!("Guard hook binary is not executable: {path}"));
    }
    Ok(())
}

fn is_executable_file(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn which_on_path(name: &str) -> bool {
    let Ok(path_var) = std::env::var("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return true;
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{name}.exe"));
            if is_executable_file(&exe) {
                return true;
            }
        }
    }
    false
}

/// Collects problems with installed hook binary paths.
#[must_use]
pub fn hook_binary_issues(home: &Path) -> Vec<String> {
    let mut issues = Vec::new();
    let mut files = vec![
        home.join(".claude").join("settings.json"),
        home.join(".cursor").join("hooks.json"),
    ];
    if let Ok(cwd) = std::env::current_dir() {
        files.push(cwd.join(".claude").join("settings.json"));
    }
    for file in files {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let mut commands = Vec::new();
        collect_hook_commands(&value, &mut commands);
        for command in commands {
            if let Some(binary) = hook_binary_path_from_command(&command) {
                if let Err(message) = check_hook_binary(&binary) {
                    if !issues.contains(&message) {
                        issues.push(message);
                    }
                }
            }
        }
    }
    issues
}

fn collect_hook_commands(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(command)) = map.get("command") {
                if is_balerx_hook_command(command) {
                    out.push(command.clone());
                }
            }
            for nested in map.values() {
                collect_hook_commands(nested, out);
            }
        }
        Value::Array(items) => {
            for nested in items {
                collect_hook_commands(nested, out);
            }
        }
        _ => {}
    }
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
        assert!(is_balerx_hook_command(
            r"'/home/user/my path/balerx' hook --event-type pre_tool_use"
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

    fn with_hook_binary(path: &str, body: impl FnOnce()) {
        HOOK_BINARY_OVERRIDE.with(|slot| {
            *slot.borrow_mut() = Some(path.to_string());
        });
        body();
        HOOK_BINARY_OVERRIDE.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn shell_quote_handles_spaces() {
        let path = "/home/user/my folder/balerx";
        let quoted = shell_quote(path);
        assert!(quoted.starts_with('\'') && quoted.ends_with('\''));
        assert!(quoted.contains("my folder"));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn shell_quote_handles_single_quotes() {
        let path = "/home/user/isn't/balerx";
        let quoted = shell_quote(path);
        assert!(quoted.contains("'\\''"));
    }

    #[test]
    fn shell_quote_windows_path_with_space() {
        let path = r"C:\Program Files\balerx\balerx.exe";
        let quoted = shell_quote(path);
        assert!(quoted.starts_with('"') && quoted.ends_with('"'));
        assert!(quoted.contains("Program Files"));
    }

    #[test]
    fn shell_quote_windows_path_with_double_quote() {
        let path = r#"C:\Program "Files"\balerx.exe"#;
        let quoted = shell_quote(path);
        assert!(quoted.contains("\"\""));
    }

    #[test]
    fn shell_quote_simple_path_unchanged() {
        let path = "/usr/local/bin/balerx";
        let quoted = shell_quote(path);
        assert_eq!(quoted, path);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn posix_path_with_backslash_and_dollar_uses_single_quotes() {
        let path = r"/tmp/foo\bar$baz/balerx";
        let quoted = shell_quote(path);
        assert_eq!(quoted, r"'/tmp/foo\bar$baz/balerx'");
        assert!(
            !quoted.starts_with('"'),
            "POSIX path must not use Windows quotes"
        );
    }

    #[test]
    fn windows_hook_command_plain_path_uses_call_operator() {
        let command = format_hook_command(r"C:\Users\bob\balerx.exe", "pre_tool_use", true);
        assert_eq!(
            command,
            r#"& "C:\Users\bob\balerx.exe" hook --event-type pre_tool_use"#
        );
    }

    #[test]
    fn windows_hook_command_path_with_space() {
        let command =
            format_hook_command(r"C:\Program Files\balerx\balerx.exe", "pre_tool_use", true);
        assert_eq!(
            command,
            r#"& "C:\Program Files\balerx\balerx.exe" hook --event-type pre_tool_use"#
        );
    }

    #[test]
    fn windows_hook_command_escapes_dollar_and_backtick() {
        let command =
            format_hook_command(r"C:\Users\bob\foo$bar`baz\balerx.exe", "pre_tool_use", true);
        assert_eq!(
            command,
            r#"& "C:\Users\bob\foo`$bar``baz\balerx.exe" hook --event-type pre_tool_use"#
        );
    }

    #[test]
    fn windows_hook_command_path_with_ampersand() {
        let command = format_hook_command(r"C:\Users\bob\foo&bar\balerx.exe", "pre_tool_use", true);
        assert_eq!(
            command,
            r#"& "C:\Users\bob\foo&bar\balerx.exe" hook --event-type pre_tool_use"#
        );
        assert!(is_balerx_hook_command(&command));
    }

    #[test]
    #[cfg(unix)]
    fn posix_exec_roundtrip_backslash_and_dollar() {
        use std::os::unix::fs::PermissionsExt;
        let home = temp_home("exec-roundtrip");
        let dir = home.join(r"sub\dir$foo");
        fs::create_dir_all(&dir).expect("dir");
        let script = dir.join("balerx");
        fs::write(&script, "#!/bin/sh\necho ROUNDTRIP_OK\n").expect("write script");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
        let quoted = quote_path(script.to_str().expect("utf8"), false);
        assert!(
            quoted.starts_with('\''),
            "expected POSIX single quotes: {quoted}"
        );
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(&quoted)
            .output()
            .expect("run quoted path");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("ROUNDTRIP_OK"),
            "quoted path failed: {quoted}\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn command_tokens_handles_escaped_single_quotes() {
        let command = "'/tmp/isn'\\''t/balerx' hook --event-type pre_tool_use";
        let tokens = command_tokens(command);
        assert!(tokens[0].contains("isn't"));
        assert_eq!(tokens[1], "hook");
    }

    #[test]
    fn command_tokens_handles_windows_escaped_quotes() {
        let command = r#""C:\Program ""Files""\balerx.exe" hook --event-type pre_tool_use"#;
        let tokens = command_tokens(command);
        assert!(tokens[0].contains("Program \"Files\""));
        assert_eq!(tokens[1], "hook");
    }

    #[test]
    fn install_uninstall_idempotency_with_space_in_path() {
        let home = temp_home("space-path");
        let installer = HookInstaller::with_home(&home);
        let awkward = if cfg!(windows) {
            r"C:\Program Files\o'brien\balerx.exe"
        } else {
            "/tmp/my dir/o'brien/balerx"
        };

        with_hook_binary(awkward, || {
            let cursor_hooks = home.join(".cursor").join("hooks.json");
            fs::create_dir_all(cursor_hooks.parent().expect("parent")).expect("dir");

            installer.install_cursor_hooks().expect("first install");
            let first_content = fs::read_to_string(&cursor_hooks).expect("read first");

            installer.install_cursor_hooks().expect("second install");
            let second_content = fs::read_to_string(&cursor_hooks).expect("read second");

            let first_hooks: Value = serde_json::from_str(&first_content).expect("parse first");
            let second_hooks: Value = serde_json::from_str(&second_content).expect("parse second");

            let first_commands: Vec<&str> = first_hooks["hooks"]["beforeShellExecution"]
                .as_array()
                .expect("array")
                .iter()
                .filter_map(|h| h["command"].as_str())
                .collect();
            let second_commands: Vec<&str> = second_hooks["hooks"]["beforeShellExecution"]
                .as_array()
                .expect("array")
                .iter()
                .filter_map(|h| h["command"].as_str())
                .collect();

            assert_eq!(first_commands.len(), second_commands.len());
            let balerx_hooks = first_commands
                .iter()
                .filter(|cmd| is_balerx_hook_command(cmd))
                .count();
            assert_eq!(balerx_hooks, 1);
            assert!(
                first_commands
                    .iter()
                    .any(|cmd| cmd.contains("my dir") || cmd.contains("Program Files")),
                "installed command should keep the spaced path: {first_commands:?}"
            );
            assert!(
                first_commands.iter().any(|cmd| cmd.contains("o'brien")
                    || cmd.contains(r"o'brien")
                    || cmd.contains("'\\''")),
                "installed command should quote the apostrophe: {first_commands:?}"
            );

            installer.uninstall_cursor_hooks().expect("uninstall");
            let after_content = fs::read_to_string(&cursor_hooks).expect("read after");
            let after_hooks: Value = serde_json::from_str(&after_content).expect("parse after");
            let after_commands: Vec<&str> = after_hooks["hooks"]
                .get("beforeShellExecution")
                .and_then(Value::as_array)
                .map(|arr| arr.iter().filter_map(|h| h["command"].as_str()).collect())
                .unwrap_or_default();

            let balerx_after = after_commands
                .iter()
                .filter(|cmd| is_balerx_hook_command(cmd))
                .count();
            assert_eq!(balerx_after, 0);
        });

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn missing_hook_binary_is_reported() {
        let issues = check_hook_binary("/definitely/missing/balerx");
        assert!(issues.is_err());
        assert!(issues.unwrap_err().contains("missing"));
    }

    #[test]
    fn hook_path_unescapes_powershell_dollar_and_backtick() {
        let command = r#"& "C:\Users\bob\foo`$bar``baz\balerx.exe" hook --event-type pre_tool_use"#;
        let path = hook_binary_path_from_command(command).expect("path");
        assert_eq!(path, r"C:\Users\bob\foo$bar`baz\balerx.exe");
    }

    #[test]
    fn hook_path_keeps_posix_backtick_in_directory() {
        let command = r"'/tmp/dir`name/balerx' hook --event-type pre_tool_use";
        let path = hook_binary_path_from_command(command).expect("path");
        assert_eq!(path, "/tmp/dir`name/balerx");
    }
}
