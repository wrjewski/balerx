use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDefinition {
    pub id: String,
    pub name: String,
    pub vendor: String,
    pub description: String,
    pub config_paths: Vec<ConfigPath>,
    pub binary_patterns: Vec<BinaryPattern>,
    pub process_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigPath {
    pub path: String,
    pub platforms: Vec<Platform>,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryPattern {
    pub path_pattern: String,
    pub platforms: Vec<Platform>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Windows,
    Macos,
    Linux,
}

impl Platform {
    #[must_use]
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::Macos
        } else {
            Platform::Linux
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub definition_id: String,
    pub name: String,
    pub version: Option<String>,
    pub path: Option<PathBuf>,
    pub config_paths: Vec<PathBuf>,
    pub status: AgentStatus,
    pub process_id: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Discovered,
    Running,
    Configured,
    NotConfigured,
}

impl AgentDefinition {
    #[must_use]
    pub fn builtin_definitions() -> Vec<Self> {
        vec![
            Self::cursor(),
            Self::claude_code(),
            Self::claude_desktop(),
            Self::vscode_copilot(),
            Self::windsurf(),
            Self::cline(),
            Self::roo_code(),
            Self::codex_cli(),
            Self::gemini_cli(),
            Self::aider(),
            Self::continue_dev(),
            Self::zed(),
            Self::goose(),
        ]
    }

    fn cursor() -> Self {
        Self {
            id: "cursor".to_string(),
            name: "Cursor".to_string(),
            vendor: "Anysphere".to_string(),
            description: "AI-first code editor".to_string(),
            config_paths: vec![
                ConfigPath {
                    path: "~/.cursor/mcp.json".to_string(),
                    platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                    required: false,
                },
                ConfigPath {
                    path: ".cursor/mcp.json".to_string(),
                    platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                    required: false,
                },
                ConfigPath {
                    path: ".cursor/hooks.json".to_string(),
                    platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                    required: false,
                },
            ],
            binary_patterns: vec![
                BinaryPattern {
                    path_pattern: "**/Cursor.app/Contents/MacOS/Cursor".to_string(),
                    platforms: vec![Platform::Macos],
                },
                BinaryPattern {
                    path_pattern: "**/Cursor.exe".to_string(),
                    platforms: vec![Platform::Windows],
                },
            ],
            process_names: vec!["Cursor".to_string(), "cursor".to_string()],
        }
    }

    fn claude_code() -> Self {
        Self {
            id: "claude-code".to_string(),
            name: "Claude Code".to_string(),
            vendor: "Anthropic".to_string(),
            description: "AI coding agent with MCP support".to_string(),
            config_paths: vec![
                ConfigPath {
                    path: "~/.claude.json".to_string(),
                    platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                    required: false,
                },
                ConfigPath {
                    path: "~/.claude/settings.json".to_string(),
                    platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                    required: false,
                },
                ConfigPath {
                    path: ".mcp.json".to_string(),
                    platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                    required: false,
                },
                ConfigPath {
                    path: ".claude/settings.json".to_string(),
                    platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                    required: false,
                },
            ],
            binary_patterns: vec![],
            process_names: vec!["claude-code".to_string(), "claude".to_string()],
        }
    }

    fn claude_desktop() -> Self {
        Self {
            id: "claude-desktop".to_string(),
            name: "Claude Desktop".to_string(),
            vendor: "Anthropic".to_string(),
            description: "Desktop application for Claude AI".to_string(),
            config_paths: vec![
                ConfigPath {
                    path: "~/Library/Application Support/Claude/claude_desktop_config.json"
                        .to_string(),
                    platforms: vec![Platform::Macos],
                    required: false,
                },
                ConfigPath {
                    path: "%APPDATA%/Claude/claude_desktop_config.json".to_string(),
                    platforms: vec![Platform::Windows],
                    required: false,
                },
            ],
            binary_patterns: vec![],
            process_names: vec!["Claude".to_string()],
        }
    }

    fn vscode_copilot() -> Self {
        Self {
            id: "vscode-copilot".to_string(),
            name: "VS Code with GitHub Copilot".to_string(),
            vendor: "Microsoft / GitHub".to_string(),
            description: "Visual Studio Code with Copilot extension".to_string(),
            config_paths: vec![
                ConfigPath {
                    path: "~/.vscode/mcp.json".to_string(),
                    platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                    required: false,
                },
                ConfigPath {
                    path: "~/Library/Application Support/Code/User/settings.json".to_string(),
                    platforms: vec![Platform::Macos],
                    required: false,
                },
                ConfigPath {
                    path: "%APPDATA%/Code/User/settings.json".to_string(),
                    platforms: vec![Platform::Windows],
                    required: false,
                },
                ConfigPath {
                    path: "~/.config/Code/User/settings.json".to_string(),
                    platforms: vec![Platform::Linux],
                    required: false,
                },
            ],
            binary_patterns: vec![],
            process_names: vec!["code".to_string(), "Code".to_string()],
        }
    }

    fn windsurf() -> Self {
        Self {
            id: "windsurf".to_string(),
            name: "Windsurf".to_string(),
            vendor: "Codeium".to_string(),
            description: "AI-powered development environment".to_string(),
            config_paths: vec![ConfigPath {
                path: "~/.windsurf/mcp_config.json".to_string(),
                platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                required: false,
            }],
            binary_patterns: vec![],
            process_names: vec!["windsurf".to_string(), "Windsurf".to_string()],
        }
    }

    fn cline() -> Self {
        Self {
            id: "cline".to_string(),
            name: "Cline (Roo Code)".to_string(),
            vendor: "Cline / Roo Code".to_string(),
            description: "VS Code extension for AI coding".to_string(),
            config_paths: vec![ConfigPath {
                path: "~/.vscode/extensions/cline_mcp_settings.json".to_string(),
                platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                required: false,
            }],
            binary_patterns: vec![],
            process_names: vec![],
        }
    }

    fn aider() -> Self {
        Self {
            id: "aider".to_string(),
            name: "Aider".to_string(),
            vendor: "Aider".to_string(),
            description: "AI pair programming in terminal".to_string(),
            config_paths: vec![
                ConfigPath {
                    path: ".aider.conf.yml".to_string(),
                    platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                    required: false,
                },
                ConfigPath {
                    path: "~/.aider.conf.yml".to_string(),
                    platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                    required: false,
                },
            ],
            binary_patterns: vec![],
            process_names: vec!["aider".to_string()],
        }
    }

    fn continue_dev() -> Self {
        Self {
            id: "continue".to_string(),
            name: "Continue".to_string(),
            vendor: "Continue".to_string(),
            description: "Open-source AI code assistant".to_string(),
            config_paths: vec![
                ConfigPath {
                    path: "~/.continue/config.yaml".to_string(),
                    platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                    required: false,
                },
                ConfigPath {
                    path: "~/.continue/config.json".to_string(),
                    platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                    required: false,
                },
            ],
            binary_patterns: vec![],
            process_names: vec![],
        }
    }

    fn zed() -> Self {
        Self {
            id: "zed".to_string(),
            name: "Zed".to_string(),
            vendor: "Zed Industries".to_string(),
            description: "Collaborative code editor with AI".to_string(),
            config_paths: vec![ConfigPath {
                path: "~/.config/zed/settings.json".to_string(),
                platforms: vec![Platform::Macos, Platform::Linux],
                required: false,
            }],
            binary_patterns: vec![],
            process_names: vec!["zed".to_string(), "Zed".to_string()],
        }
    }

    fn goose() -> Self {
        Self {
            id: "goose".to_string(),
            name: "Goose".to_string(),
            vendor: "Block".to_string(),
            description: "AI coding agent".to_string(),
            config_paths: vec![ConfigPath {
                path: "~/.config/goose/config.yaml".to_string(),
                platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                required: false,
            }],
            binary_patterns: vec![],
            process_names: vec!["goose".to_string()],
        }
    }

    fn roo_code() -> Self {
        Self {
            id: "roo-code".to_string(),
            name: "Roo Code".to_string(),
            vendor: "Roo Code".to_string(),
            description: "AI coding assistant VS Code extension".to_string(),
            config_paths: vec![
                ConfigPath {
                    path: "~/.vscode/extensions/rooveterinaryinc.roo-cline-*/mcp_settings.json".to_string(),
                    platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                    required: false,
                },
                ConfigPath {
                    path: "~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings.json".to_string(),
                    platforms: vec![Platform::Macos],
                    required: false,
                },
                ConfigPath {
                    path: "%APPDATA%/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings.json".to_string(),
                    platforms: vec![Platform::Windows],
                    required: false,
                },
                ConfigPath {
                    path: "~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings.json".to_string(),
                    platforms: vec![Platform::Linux],
                    required: false,
                },
            ],
            binary_patterns: vec![],
            process_names: vec!["code".to_string()],
        }
    }

    fn codex_cli() -> Self {
        Self {
            id: "codex-cli".to_string(),
            name: "Codex CLI".to_string(),
            vendor: "OpenAI / GitHub".to_string(),
            description: "Command-line interface for OpenAI Codex".to_string(),
            config_paths: vec![
                ConfigPath {
                    path: "~/.codex/config.toml".to_string(),
                    platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                    required: false,
                },
                ConfigPath {
                    path: "~/.config/codex/config.toml".to_string(),
                    platforms: vec![Platform::Linux],
                    required: false,
                },
            ],
            binary_patterns: vec![],
            process_names: vec!["codex".to_string()],
        }
    }

    fn gemini_cli() -> Self {
        Self {
            id: "gemini-cli".to_string(),
            name: "Gemini CLI".to_string(),
            vendor: "Google".to_string(),
            description: "Command-line interface for Google Gemini".to_string(),
            config_paths: vec![
                ConfigPath {
                    path: "~/.gemini/settings.json".to_string(),
                    platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
                    required: false,
                },
                ConfigPath {
                    path: "~/.config/gemini/settings.json".to_string(),
                    platforms: vec![Platform::Linux],
                    required: false,
                },
                ConfigPath {
                    path: "~/Library/Application Support/Gemini/settings.json".to_string(),
                    platforms: vec![Platform::Macos],
                    required: false,
                },
            ],
            binary_patterns: vec![],
            process_names: vec!["gemini".to_string()],
        }
    }

    #[must_use]
    pub fn expand_path(&self, path_str: &str) -> Option<PathBuf> {
        let path_str = if path_str.starts_with('~') {
            {
                let home = dirs::home_dir()?;
                path_str.replacen('~', &home.to_string_lossy(), 1)
            }
        } else if cfg!(windows) && path_str.contains("%APPDATA%") {
            if let Ok(appdata) = std::env::var("APPDATA") {
                path_str.replace("%APPDATA%", &appdata)
            } else {
                return None;
            }
        } else {
            path_str.to_string()
        };

        Some(PathBuf::from(path_str))
    }
}
