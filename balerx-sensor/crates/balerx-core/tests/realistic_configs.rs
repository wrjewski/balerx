use balerx_core::config::{inspect_contents, IssueType};
use balerx_core::secret::SecretDetector;
use std::path::Path;

fn issues(name: &str, body: &str) -> Vec<IssueType> {
    inspect_contents(Path::new(name), body)
        .issues
        .into_iter()
        .map(|issue| issue.issue_type)
        .collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn realistic_mcp_and_agent_configs() {
    let npm = issues(
        "mcp.json",
        r#"{
          "mcpServers": {
            "scoped": {"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]},
            "yes": {"command":"npx","args":["--yes","github-mcp"]},
            "latest": {"command":"npx","args":["-y","some-package@latest"]},
            "pinned": {"command":"npx","args":["-y","@scope/pkg@1.2.3"]},
            "uv": {"command":"uvx","args":["pkg==2025.1.0"]},
            "uv-open": {"command":"uvx","args":["loose-pkg"]}
          }
        }"#,
    );
    assert!(npm.contains(&IssueType::UnpinnedPackage));
    assert_eq!(
        npm.iter()
            .filter(|kind| **kind == IssueType::LatestTag)
            .count(),
        1
    );
    assert!(
        !npm.iter()
            .any(|kind| matches!(kind, IssueType::UnpinnedPackage))
            || npm
                .iter()
                .filter(|kind| **kind == IssueType::UnpinnedPackage)
                .count()
                >= 3
    );
    let unpinned = npm
        .iter()
        .filter(|kind| **kind == IssueType::UnpinnedPackage)
        .count();
    assert_eq!(unpinned, 3, "scoped, --yes package, and loose uvx");
    assert!(!issues(
        "pinned.json",
        r#"{"mcpServers":{"ok":{"command":"uvx","args":["pkg==2025.1.0"]}}}"#
    )
    .contains(&IssueType::UnpinnedPackage));

    let vscode = issues(
        ".vscode/mcp.json",
        r#"{"servers":{"files":{"command":"npx","args":["-y","server","$HOME"]}}}"#,
    );
    assert!(vscode.contains(&IssueType::UnpinnedPackage));
    assert!(vscode.contains(&IssueType::BroadFilesystem));

    let home = issues(
        "home.json",
        r#"{"mcpServers":{"files":{"command":"npx","args":["-y","server@1.0.0","/home/dev"]}}}"#,
    );
    assert!(home.contains(&IssueType::BroadFilesystem));
    assert!(!home.contains(&IssueType::UnpinnedPackage));

    let remote = issues(
        "remote.json",
        r#"{
          "mcpServers": {
            "sneaky": {"url":"http://localhost.attacker.example/mcp"},
            "local": {"url":"http://localhost:8080/mcp"},
            "open": {"url":"https://mcp.example.com/rpc"}
          }
        }"#,
    );
    assert!(remote.contains(&IssueType::PlainHttp));
    assert!(remote.contains(&IssueType::NoAuth));
    assert_eq!(
        remote
            .iter()
            .filter(|kind| **kind == IssueType::PlainHttp)
            .count(),
        1
    );

    let docker = issues(
        "docker.json",
        r#"{"mcpServers":{"box":{"command":"docker","args":["run","--privileged","-v","/:/host","image:latest"]}}}"#,
    );
    assert!(docker.contains(&IssueType::DockerPrivileged));
    assert!(docker.contains(&IssueType::RootMount));
    assert!(docker.contains(&IssueType::LatestTag));
    assert!(!docker.contains(&IssueType::UnpinnedPackage));

    let codex = issues(
        "config.toml",
        r#"
approval_policy = "never"
sandbox_mode = "danger-full-access"

[mcp_servers.files]
command = "npx"
args = ["-y", "server@1.2.3", "/home/dev"]
"#,
    );
    assert!(codex.contains(&IssueType::AutoApprove));
    assert!(codex.contains(&IssueType::DangerousPermissions));
    assert!(codex.contains(&IssueType::BroadFilesystem));

    let claude = issues(
        "settings.json",
        r#"{"permissions":{"defaultMode":"bypassPermissions","allow":["Bash(*)"]}}"#,
    );
    assert_eq!(
        claude
            .iter()
            .filter(|kind| **kind == IssueType::DangerousPermissions)
            .count(),
        2
    );

    let broken = issues("broken.json", "{ this is not json");
    assert_eq!(broken, vec![IssueType::BrokenConfig]);
}

#[test]
fn modern_secret_shapes_are_found_once() {
    let detector = SecretDetector::new().expect("detector");
    let text = [
        ["OPENAI=", "sk-proj-", "abcDEF1234567890_xyz"].concat(),
        ["ANTHROPIC=", "sk-ant-", "api03-abc_def-1234567890"].concat(),
        ["SLACK=", "xoxb-", "1234567890-abcdefghij"].concat(),
        ["STRIPE=", "sk_live_", "abcDEF1234567890"].concat(),
        ["GH=", "github_pat_", "11AAAAAAA0bbbbbbbbbbbbbbbbbbbb"].concat(),
        [
            "DB=postgresql://app:",
            "s3cr3t-pass",
            "@db.internal:5432/app",
        ]
        .concat(),
        "GENERIC_API_KEY=abcdefghijklmnopqrstuv".to_string(),
    ]
    .join("\n");
    let matches = detector.scan_text(&text, "fixture");
    for name in [
        "OpenAI Project Key",
        "Anthropic API Key",
        "Slack Bot Token",
        "Stripe Secret Key",
        "GitHub Fine-Grained PAT",
        "URL Password",
        "Generic API Key",
    ] {
        let count = matches
            .iter()
            .filter(|item| item.pattern_name == name)
            .count();
        assert_eq!(count, 1, "{name} count");
    }
}
