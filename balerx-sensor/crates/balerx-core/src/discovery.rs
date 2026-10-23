use crate::agent::{Agent, AgentDefinition, AgentStatus, Platform};
use crate::config::{self, McpConfig};
use crate::secret::SecretDetector;
use std::path::PathBuf;
use tracing::{debug, info};

pub struct AgentDiscovery {
    definitions: Vec<AgentDefinition>,
    current_platform: Platform,
}

impl AgentDiscovery {
    #[must_use]
    pub fn new() -> Self {
        Self {
            definitions: AgentDefinition::builtin_definitions(),
            current_platform: Platform::current(),
        }
    }

    pub fn discover_all(&self) -> Vec<Agent> {
        let mut discovered = Vec::new();

        for def in &self.definitions {
            if let Some(agent) = self.discover_agent(def) {
                discovered.push(agent);
            }
        }

        info!("Discovered {} agents", discovered.len());
        discovered
    }

    fn discover_agent(&self, def: &AgentDefinition) -> Option<Agent> {
        let mut config_paths = Vec::new();
        let mut found_any = false;

        for config in &def.config_paths {
            if !config.platforms.contains(&self.current_platform) {
                continue;
            }

            for expanded in def.expand_config_paths(&config.path) {
                if expanded.is_file() {
                    debug!("Found config for {}: {:?}", def.name, expanded);
                    remember_config(&mut config_paths, expanded);
                    found_any = true;
                }
            }
        }

        if !found_any && !self.is_agent_likely_installed(def) {
            return None;
        }

        let status = if config_paths.is_empty() {
            AgentStatus::Discovered
        } else {
            AgentStatus::Configured
        };

        Some(Agent {
            definition_id: def.id.clone(),
            name: def.name.clone(),
            version: None,
            path: None,
            config_paths,
            status,
            process_id: None,
        })
    }

    fn is_agent_likely_installed(&self, def: &AgentDefinition) -> bool {
        if def.id == "cursor" {
            if let Some(home) = dirs::home_dir() {
                if home.join(".cursor").is_dir() {
                    return true;
                }
            }
        }

        if def.binary_patterns.is_empty() && def.process_names.is_empty() {
            return false;
        }

        for pattern in &def.binary_patterns {
            if !pattern.platforms.contains(&self.current_platform) {
                continue;
            }

            if let Some(binary_path) = Self::find_binary(&pattern.path_pattern) {
                debug!("Found binary for {}: {:?}", def.name, binary_path);
                return true;
            }
        }

        false
    }

    // macOS .app extension is case-sensitive by convention
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn find_binary(pattern: &str) -> Option<PathBuf> {
        if cfg!(target_os = "macos") && pattern.contains(".app") {
            let applications = PathBuf::from("/Applications");
            if let Some(app_name) = pattern.split('/').find(|s| s.ends_with(".app")) {
                let app_path = applications.join(app_name);
                if app_path.exists() {
                    return Some(app_path);
                }
            }
        } else if cfg!(target_os = "windows") && pattern.contains(".exe") {
            let program_files = std::env::var("ProgramFiles").ok()?;
            let program_files_x86 = std::env::var("ProgramFiles(x86)").ok();
            let local_app_data = std::env::var("LOCALAPPDATA").ok();

            let search_paths = vec![Some(program_files), program_files_x86, local_app_data];

            for base in search_paths.into_iter().flatten() {
                let base_path = PathBuf::from(base);
                if let Some(exe_name) = pattern.split("**").last() {
                    let exe_name = exe_name.trim_start_matches('/').trim_start_matches('\\');
                    if let Some(entry) = walkdir::WalkDir::new(&base_path)
                        .max_depth(3)
                        .into_iter()
                        .filter_map(Result::ok)
                        .find(|e| e.file_name().to_string_lossy() == exe_name)
                    {
                        return Some(entry.path().to_path_buf());
                    }
                }
            }
        }

        None
    }
}

fn remember_config(paths: &mut Vec<PathBuf>, expanded: PathBuf) {
    let canonical = expanded.canonicalize().unwrap_or(expanded);
    if paths.iter().any(|existing| existing == &canonical) {
        return;
    }
    paths.push(canonical);
}

impl Default for AgentDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ConfigScanner {
    secret_detector: SecretDetector,
}

impl ConfigScanner {
    /// Create a new config scanner
    ///
    /// # Errors
    /// Returns an error if the secret detector cannot be initialized
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            secret_detector: SecretDetector::new()?,
        })
    }

    /// Scan a configuration file for issues
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed
    pub fn scan_config(&self, path: &PathBuf) -> anyhow::Result<ScanConfigResult> {
        let mut result = ScanConfigResult {
            path: path.clone(),
            mcp_config: None,
            secrets_found: Vec::new(),
            issues: Vec::new(),
        };

        let content = std::fs::read_to_string(path)?;
        let inspected = config::inspect_contents(path, &content);
        result.issues = inspected.issues;
        result.mcp_config = inspected.mcp;
        let location = path.to_string_lossy();
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            result.secrets_found = self.secret_detector.scan_json(&json, &location);
        } else {
            result.secrets_found = self.secret_detector.scan_text(&content, &location);
        }

        Ok(result)
    }
}

impl Default for ConfigScanner {
    fn default() -> Self {
        Self::new().expect("Failed to create config scanner")
    }
}

#[derive(Debug)]
pub struct ScanConfigResult {
    pub path: PathBuf,
    #[allow(dead_code)]
    pub mcp_config: Option<McpConfig>,
    pub secrets_found: Vec<crate::secret::SecretMatch>,
    pub issues: Vec<crate::config::ConfigIssue>,
}

#[cfg(test)]
mod tests {
    use super::remember_config;
    use std::fs;

    #[test]
    fn the_same_config_file_is_recorded_once() {
        let root = std::env::temp_dir().join(format!("balerx-dedupe-{}", std::process::id()));
        fs::create_dir_all(&root).expect("dir");
        let file = root.join("mcp.json");
        fs::write(&file, "{}").expect("file");
        let mut paths = Vec::new();
        remember_config(&mut paths, file.clone());
        remember_config(&mut paths, root.join(".").join("mcp.json"));
        assert_eq!(paths.len(), 1);
        fs::remove_dir_all(&root).ok();
    }
}
