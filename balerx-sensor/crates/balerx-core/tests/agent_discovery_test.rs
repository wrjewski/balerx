use balerx_core::agent::{AgentDefinition, Platform};

#[test]
fn test_builtin_agent_definitions() {
    let definitions = AgentDefinition::builtin_definitions();

    assert!(
        definitions.len() >= 10,
        "Should have at least 10 agent definitions"
    );

    let cursor = definitions.iter().find(|d| d.id == "cursor");
    assert!(cursor.is_some(), "Cursor definition should exist");

    let cursor = cursor.unwrap();
    assert_eq!(cursor.name, "Cursor");
    assert_eq!(cursor.vendor, "Anysphere");
    assert!(!cursor.config_paths.is_empty(), "Should have config paths");
}

#[test]
fn test_agent_definition_cursor() {
    let cursor = AgentDefinition::builtin_definitions()
        .into_iter()
        .find(|d| d.id == "cursor")
        .expect("Cursor definition");

    let has_global_config = cursor
        .config_paths
        .iter()
        .any(|c| c.path.contains(".cursor/mcp.json"));
    assert!(
        has_global_config,
        "Should have global .cursor/mcp.json config"
    );

    let has_project_config = cursor
        .config_paths
        .iter()
        .any(|c| c.path == ".cursor/mcp.json");
    assert!(
        has_project_config,
        "Should have project-level .cursor/mcp.json config"
    );
}

#[test]
fn test_agent_definition_claude_code() {
    let claude = AgentDefinition::builtin_definitions()
        .into_iter()
        .find(|d| d.id == "claude-code")
        .expect("Claude Code definition");

    assert_eq!(claude.name, "Claude Code");
    assert_eq!(claude.vendor, "Anthropic");

    let has_claude_json = claude
        .config_paths
        .iter()
        .any(|c| c.path.contains(".claude.json"));
    assert!(has_claude_json, "Should have .claude.json config");
}

#[test]
fn test_platform_current() {
    let platform = Platform::current();

    #[cfg(target_os = "windows")]
    assert_eq!(platform, Platform::Windows);

    #[cfg(target_os = "macos")]
    assert_eq!(platform, Platform::Macos);

    #[cfg(target_os = "linux")]
    assert_eq!(platform, Platform::Linux);
}

#[test]
fn test_path_expansion_tilde() {
    let def = AgentDefinition::builtin_definitions()[0].clone();
    let expanded = def.expand_path("~/.config/test");
    assert!(expanded.is_some(), "Should expand ~ to home directory");

    let path = expanded.unwrap();
    assert!(
        !path.to_string_lossy().contains('~'),
        "~ should be expanded"
    );
}

#[cfg(windows)]
#[test]
fn test_path_expansion_windows_env() {
    let def = AgentDefinition::builtin_definitions()[0].clone();
    let expanded = def.expand_path("%APPDATA%/test");
    assert!(expanded.is_some(), "Should expand %APPDATA%");

    let path = expanded.unwrap();
    assert!(
        !path.to_string_lossy().contains("%APPDATA%"),
        "%APPDATA% should be expanded"
    );
}
