use anyhow::{Context, Result};
use balerx_core::{
    canary::{CanaryManager, CanaryType},
    config::ConfigIssue,
    discovery::{AgentDiscovery, ConfigScanner},
    finding::{Confidence, Finding, FindingSeverity, ScanResult},
    guard::{AgentType, HookInstaller},
    lockfile::{DriftType, LockedAgent, Lockfile},
    log::{ActivityEvent, ActivityLog},
    output::{terminal, write_html, write_json, write_sarif},
    poison::PoisonDetector,
    policy::{HookEvent, HookEventType, Policy},
    process::ProcessCollector,
    rules::RuleId,
};
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashMap;
use std::io::{self};
use std::path::PathBuf;
use tracing::info;

#[derive(Parser)]
#[command(name = "balerx")]
#[command(about = "Balerx Gate - Security scanner for AI coding agents", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan the system for AI agents and security issues
    Scan {
        /// Output JSON to file
        #[arg(long, value_name = "FILE")]
        json: Option<PathBuf>,

        /// Output SARIF to file
        #[arg(long, value_name = "FILE")]
        sarif: Option<PathBuf>,

        /// Output HTML report to file
        #[arg(long, value_name = "FILE")]
        html: Option<PathBuf>,

        /// Quiet mode - only output files, no terminal
        #[arg(short, long)]
        quiet: bool,
    },

    /// Generate or update agent lockfile
    Lock {
        /// Output lockfile path
        #[arg(short, long, default_value = "balerx.lock")]
        output: PathBuf,
    },

    /// Show diff between current state and lockfile
    Diff {
        /// Lockfile to compare against
        #[arg(short, long, default_value = "balerx.lock")]
        lockfile: PathBuf,
    },

    /// Guard hooks management
    Guard {
        #[command(subcommand)]
        command: GuardCommands,
    },

    /// Hook handler (called by agent hooks)
    Hook {
        /// Event type
        #[arg(long)]
        event_type: String,
    },

    /// Activity log management
    Log {
        #[command(subcommand)]
        command: LogCommands,
    },

    /// Canary credential management
    Canary {
        #[command(subcommand)]
        command: CanaryCommands,
    },

    /// Upload scan results or Guard activity-log metadata to a Monitor project
    Upload {
        /// API base URL from your Balerx Gate dashboard onboarding.
        /// No host is compiled in. Overrides `BALERX_API_URL` when set.
        #[arg(long)]
        api_url: Option<String>,

        /// Project ingest API key (hashed at rest on the server)
        #[arg(long)]
        api_key: Option<String>,

        /// Findings v1 JSON produced by `balerx scan --json`
        #[arg(long)]
        scan: Option<PathBuf>,

        /// Guard activity log (JSONL). Tool arguments are dropped before upload.
        #[arg(long)]
        activity_log: Option<PathBuf>,

        /// Lockfile to diff. Drift is attached to the scan upload.
        #[arg(long)]
        lockfile: Option<PathBuf>,
    },

    /// Manage the local Guard policy. Offline unless you explicitly pull.
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Fetch the organization policy with an ingest key and write it locally.
    ///
    /// Does not contact the network unless `--api-url` and `--api-key` (or
    /// `BALERX_API_URL` and `BALERX_API_KEY`) are set.
    Pull {
        /// API base URL from your Balerx Gate dashboard onboarding.
        /// No host is compiled in. Overrides `BALERX_API_URL` when set.
        #[arg(long)]
        api_url: Option<String>,

        /// Project ingest or enrollment API key
        #[arg(long)]
        api_key: Option<String>,

        /// Destination. Defaults to `~/.balerx/policy.yaml`.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum GuardCommands {
    /// Install guard hooks for an agent
    Install {
        /// Agent type to install hooks for
        #[arg(value_enum)]
        agent: CliAgentType,
    },

    /// Uninstall guard hooks for an agent
    Uninstall {
        /// Agent type to uninstall hooks for
        #[arg(value_enum)]
        agent: CliAgentType,
    },
}

#[derive(Subcommand)]
enum LogCommands {
    /// View recent activity
    View {
        /// Number of entries to show
        #[arg(short, long, default_value = "50")]
        limit: usize,

        /// Filter by agent name
        #[arg(short, long)]
        agent: Option<String>,

        /// Filter by event type
        #[arg(short = 't', long)]
        event_type: Option<String>,
    },
}

#[derive(Subcommand)]
enum CanaryCommands {
    /// Plant a canary credential
    Plant {
        /// Type of canary to plant
        #[arg(value_enum)]
        canary_type: CliCanaryType,

        /// Location to plant the canary
        #[arg(short, long)]
        location: Option<PathBuf>,
    },

    /// Remove a canary credential
    Remove {
        /// Canary ID to remove
        canary_id: String,
    },

    /// List all planted canaries
    List,

    /// Check if a path is a canary
    Check {
        /// Path to check
        path: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliAgentType {
    ClaudeCode,
    Cursor,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliCanaryType {
    Aws,
    Env,
    Ssh,
    Generic,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .with_level(true)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            json,
            sarif,
            html,
            quiet,
        } => {
            run_scan(json, sarif, html, quiet)?;
        }
        Commands::Lock { output } => {
            run_lock(&output)?;
        }
        Commands::Diff { lockfile } => {
            run_diff(&lockfile)?;
        }
        Commands::Guard { command } => {
            run_guard(&command)?;
        }
        Commands::Hook { event_type } => {
            run_hook(&event_type)?;
        }
        Commands::Log { command } => {
            run_log(command)?;
        }
        Commands::Canary { command } => {
            run_canary(command)?;
        }
        Commands::Upload {
            api_url,
            api_key,
            scan,
            activity_log,
            lockfile,
        } => {
            run_upload(
                api_url,
                api_key,
                scan.as_ref(),
                activity_log,
                lockfile.as_ref(),
            )?;
        }
        Commands::Policy { command } => match command {
            PolicyCommands::Pull {
                api_url,
                api_key,
                output,
            } => {
                run_policy_pull(api_url, api_key, output)?;
            }
        },
    }

    Ok(())
}

// Main scan orchestration: length is acceptable for sequential workflow
#[allow(clippy::too_many_lines)]
fn run_scan(
    json_path: Option<PathBuf>,
    sarif_path: Option<PathBuf>,
    html_path: Option<PathBuf>,
    quiet: bool,
) -> Result<()> {
    info!("Starting Balerx Gate security scan");

    let mut result = ScanResult::new();

    let discovery = AgentDiscovery::new();
    let agents = discovery.discover_all();

    for agent in agents {
        result.add_agent(agent);
    }

    let config_scanner = ConfigScanner::new()?;

    let agent_configs: Vec<_> = result
        .agents
        .iter()
        .flat_map(|agent| {
            agent
                .config_paths
                .iter()
                .map(move |path| (agent.name.clone(), path.clone()))
        })
        .collect();

    for (agent_name, config_path) in agent_configs {
        info!("Scanning config: {:?}", config_path);

        match config_scanner.scan_config(&config_path) {
            Ok(scan_result) => {
                for secret in scan_result.secrets_found {
                    let finding = Finding::new(
                        RuleId::SecretInConfig,
                        match secret.severity {
                            balerx_core::secret::SecretSeverity::Critical => FindingSeverity::Critical,
                            balerx_core::secret::SecretSeverity::High => FindingSeverity::High,
                            balerx_core::secret::SecretSeverity::Medium => FindingSeverity::Medium,
                        },
                        format!("Secret found: {}", secret.pattern_name),
                        format!("Found {} in configuration file", secret.pattern_name),
                    )
                    .with_agent(&agent_name)
                    .with_resource(config_path.to_string_lossy().to_string())
                    .with_evidence(serde_json::json!({
                        "redacted_value": secret.redacted_value,
                        "location": secret.location
                    }))
                    .with_fix("Move this secret to a secure credential store (OS keychain, environment variable, or vault)");

                    result.add_finding(finding);
                }

                for issue in scan_result.issues {
                    let (severity, rule_id, fix) = map_config_issue(&issue);

                    let finding = Finding::new(
                        rule_id,
                        severity,
                        issue.description.clone(),
                        "MCP server configuration issue detected".to_string(),
                    )
                    .with_agent(&agent_name)
                    .with_resource(config_path.to_string_lossy().to_string())
                    .with_evidence(serde_json::json!({
                        "server_name": issue.server_name,
                        "resource": issue.resource
                    }))
                    .with_fix(fix)
                    .with_confidence(Confidence::High);

                    result.add_finding(finding);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to scan config {:?}: {}", config_path, e);
            }
        }
    }

    let mut process_collector = ProcessCollector::new();
    let all_process_names: Vec<String> = result
        .agents
        .iter()
        .flat_map(|a| vec![a.name.clone(), a.definition_id.clone()])
        .collect();

    let running_processes = process_collector.find_agent_processes(&all_process_names);

    for process in &running_processes {
        info!(
            "Found running agent process: {} (PID: {})",
            process.name, process.pid
        );
    }

    let poison_detector = PoisonDetector::new()?;
    if let Ok(current_dir) = std::env::current_dir() {
        if let Ok(poison_matches) = poison_detector.scan_directory(&current_dir) {
            for poison in poison_matches {
                let finding = Finding::new(
                    RuleId::ToolPoisonHiddenInstructions,
                    match poison.severity {
                        balerx_core::poison::PoisonSeverity::Critical => FindingSeverity::Critical,
                        balerx_core::poison::PoisonSeverity::High => FindingSeverity::High,
                        balerx_core::poison::PoisonSeverity::Medium => FindingSeverity::Medium,
                    },
                    format!("Suspicious instruction detected: {}", poison.pattern_name),
                    "Found potentially malicious pattern in agent configuration file".to_string(),
                )
                .with_resource(poison.location)
                .with_evidence(serde_json::json!({
                    "pattern": poison.pattern_name,
                    "context": poison.context
                }))
                .with_fix("Review this instruction and remove it if it was not intentionally added")
                .with_confidence(Confidence::Medium);

                result.add_finding(finding);
            }
        }
    }

    if json_path.is_some() || sarif_path.is_some() || html_path.is_some() {
        if let Some(path) = json_path {
            write_json(&result, &path)?;
            if !quiet {
                println!("JSON output written to: {}", path.display());
            }
        }

        if let Some(path) = sarif_path {
            write_sarif(&result, &path)?;
            if !quiet {
                println!("SARIF output written to: {}", path.display());
            }
        }

        if let Some(path) = html_path {
            write_html(&result, &path)?;
            if !quiet {
                println!("HTML report written to: {}", path.display());
            }
        }
    }

    if !quiet {
        terminal::print_scan_result(&result);
    }

    info!("Scan complete");

    if result.summary.critical_count > 0 {
        std::process::exit(2);
    } else if result.summary.high_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn map_config_issue(issue: &ConfigIssue) -> (FindingSeverity, RuleId, &'static str) {
    use balerx_core::config::IssueType;

    match issue.issue_type {
        IssueType::UnpinnedPackage => (
            FindingSeverity::Medium,
            RuleId::McpSupplyUnpinned,
            "Pin the package to a specific version, e.g., npx -y package@1.2.3",
        ),
        IssueType::LatestTag => (
            FindingSeverity::Medium,
            RuleId::McpSupplyLatest,
            "Replace @latest with a specific version number",
        ),
        IssueType::PlainHttp => (
            FindingSeverity::High,
            RuleId::McpRemotePlainHttp,
            "Use HTTPS instead of plain HTTP for remote connections",
        ),
        IssueType::BroadFilesystem => (
            FindingSeverity::High,
            RuleId::McpPermBroadFilesystem,
            "Restrict filesystem access to specific directories needed by the tool",
        ),
        IssueType::NoAuth => (
            FindingSeverity::Medium,
            RuleId::McpRemoteNoAuth,
            "Add authentication credentials for remote MCP server connections",
        ),
    }
}

fn discovered_lockfile() -> Lockfile {
    let mut lockfile = Lockfile::new();
    let discovery = AgentDiscovery::new();
    for agent in discovery.discover_all() {
        lockfile.add_agent(LockedAgent {
            name: agent.name.clone(),
            definition_id: agent.definition_id.clone(),
            version: agent.version.clone(),
            config_paths: agent
                .config_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            config_hash: None,
        });
    }
    lockfile
}

fn run_lock(output: &PathBuf) -> Result<()> {
    info!("Generating agent lockfile");

    let lockfile = discovered_lockfile();

    lockfile.to_file(output)?;

    println!("✓ Lockfile generated: {}", output.display());
    println!("  Agents locked: {}", lockfile.agents.len());
    println!("  MCP servers locked: {}", lockfile.mcp_servers.len());
    println!("\nCommit this file to track agent configuration changes.");

    Ok(())
}

fn run_diff(lockfile_path: &PathBuf) -> Result<()> {
    info!("Checking for drift");

    if !lockfile_path.exists() {
        anyhow::bail!(
            "Lockfile not found: {}. Run 'balerx lock' first.",
            lockfile_path.display()
        );
    }

    let old_lockfile = Lockfile::from_file(lockfile_path)?;
    let new_lockfile = discovered_lockfile();
    let drifts = old_lockfile.diff(&new_lockfile);

    if drifts.is_empty() {
        println!("✓ No drift detected - configuration matches lockfile");
        return Ok(());
    }

    println!(
        "⚠ Configuration drift detected ({} changes):\n",
        drifts.len()
    );

    for drift in &drifts {
        let severity_marker = match drift.severity() {
            balerx_core::lockfile::DriftSeverity::High => "🔴 HIGH",
            balerx_core::lockfile::DriftSeverity::Medium => "🟡 MEDIUM",
            balerx_core::lockfile::DriftSeverity::Low => "🔵 LOW",
            balerx_core::lockfile::DriftSeverity::Info => "ℹ INFO",
        };
        println!("{}: {}", severity_marker, drift.message());
    }

    println!("\nRun 'balerx lock' to update the lockfile with current state.");

    std::process::exit(1);
}

fn run_guard(command: &GuardCommands) -> Result<()> {
    let installer = HookInstaller::new();

    match command {
        GuardCommands::Install { agent } => {
            let agent_type = match agent {
                CliAgentType::ClaudeCode => AgentType::ClaudeCode,
                CliAgentType::Cursor => AgentType::Cursor,
            };

            println!("Installing Guard hooks for {agent_type:?}...");
            installer.install(agent_type)?;
            println!("✓ Guard hooks installed successfully");
            println!("\nThe hooks will intercept:");
            match agent_type {
                AgentType::ClaudeCode => {
                    println!("  • PreToolUse - before each tool execution");
                    println!("  • PostToolUse - after each tool execution");
                }
                AgentType::Cursor => {
                    println!("  • beforeShellExecution - before shell commands");
                    println!("  • beforeMCPExecution - before MCP tool calls");
                }
            }
            println!("\nPolicy file: ~/.balerx/policy.yaml");
            println!(
                "Activity log: {}",
                ActivityLog::default_log().path().display()
            );
        }
        GuardCommands::Uninstall { agent } => {
            let agent_type = match agent {
                CliAgentType::ClaudeCode => AgentType::ClaudeCode,
                CliAgentType::Cursor => AgentType::Cursor,
            };

            println!("Uninstalling Guard hooks for {agent_type:?}...");
            installer.uninstall(agent_type)?;
            println!("✓ Guard hooks uninstalled successfully");
        }
    }

    Ok(())
}

fn run_hook(event_type: &str) -> Result<()> {
    let start = std::time::Instant::now();

    let stdin = io::stdin();
    let input: serde_json::Value = serde_json::from_reader(stdin.lock())?;

    let policy_path = default_policy_path();

    let policy = if policy_path.exists() {
        Policy::from_file(&policy_path)?
    } else {
        Policy::default_policy()
    };

    let event = parse_hook_event(event_type, &input);

    let canary_manager = CanaryManager::new()?;
    if let Some(resource) = &event.resource {
        if let Some(canary) = canary_manager.is_canary(resource) {
            let activity_log = ActivityLog::default_log();
            let log_event = ActivityEvent::new("canary_access", &event.agent, "denied")
                .with_resource(resource)
                .with_decision("CANARY TRIGGERED")
                .with_metadata(guard_activity_metadata(
                    &input,
                    &serde_json::json!({
                        "canary_id": canary.id,
                        "canary_type": canary.canary_type,
                        "severity": "CRITICAL"
                    }),
                ));
            let _ = activity_log.append(log_event);

            let response = serde_json::json!({
                "allow": false,
                "reason": "Access to canary credential detected - possible security breach"
            });
            println!("{}", serde_json::to_string(&response)?);
            return Ok(());
        }
    }

    let decision = policy.evaluate(&event);

    let activity_log = ActivityLog::default_log();
    let log_event = ActivityEvent::new(event_type, &event.agent, "evaluated")
        .with_resource(event.resource.clone().unwrap_or_default())
        .with_decision(format!("{:?}", decision.action))
        .with_metadata(guard_activity_metadata(
            &input,
            &serde_json::json!({
                "matched_rule": decision.matched_rule,
                "elapsed_ms": start.elapsed().as_millis()
            }),
        ));

    let _ = activity_log.append(log_event);

    let response = match decision.action {
        balerx_core::policy::PolicyAction::Allow => serde_json::json!({
            "allow": true,
            "reason": decision.reason
        }),
        balerx_core::policy::PolicyAction::Deny => serde_json::json!({
            "allow": false,
            "reason": decision.reason
        }),
        balerx_core::policy::PolicyAction::Ask => serde_json::json!({
            "allow": false,
            "reason": format!("User approval required: {}", decision.reason)
        }),
    };

    println!("{}", serde_json::to_string(&response)?);

    let elapsed = start.elapsed();
    if elapsed.as_millis() > 50 {
        tracing::warn!(
            "Hook evaluation took {}ms (target: <50ms)",
            elapsed.as_millis()
        );
    }

    Ok(())
}

fn parse_hook_event(event_type: &str, input: &serde_json::Value) -> HookEvent {
    let hook_event_type = match event_type {
        "before_shell_execution" => HookEventType::ShellExecution,
        "before_mcp_execution" => HookEventType::McpExecution,
        _ => HookEventType::ToolCall,
    };

    let metadata: HashMap<String, serde_json::Value> =
        input.as_object().map_or_else(HashMap::default, |obj| {
            obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        });

    HookEvent {
        event_type: hook_event_type,
        agent: input
            .get("agent")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        resource: input
            .get("resource")
            .or_else(|| input.get("path"))
            .and_then(|v| v.as_str())
            .map(String::from),
        command: input
            .get("command")
            .and_then(|v| v.as_str())
            .map(String::from),
        mcp_server: input
            .get("server")
            .and_then(|v| v.as_str())
            .map(String::from),
        tool_name: input.get("tool").and_then(|v| v.as_str()).map(String::from),
        metadata,
    }
}

fn run_log(command: LogCommands) -> Result<()> {
    let log = ActivityLog::default_log();

    match command {
        LogCommands::View {
            limit,
            agent,
            event_type,
        } => {
            let events = log.filter(agent.as_deref(), event_type.as_deref(), limit)?;

            if events.is_empty() {
                println!("No activity logged yet.");
                return Ok(());
            }

            println!("Recent activity (showing {} entries):\n", events.len());

            for event in events {
                println!("┌─ {} [{}]", event.timestamp, event.event_type);
                println!("│  Agent: {}", event.agent);
                println!("│  Action: {}", event.action);
                if let Some(resource) = &event.resource {
                    println!("│  Resource: {resource}");
                }
                if let Some(decision) = &event.decision {
                    println!("│  Decision: {decision}");
                }
                println!("└─ ID: {}\n", event.event_id);
            }
        }
    }

    Ok(())
}

fn run_canary(command: CanaryCommands) -> Result<()> {
    let mut manager = CanaryManager::new()?;

    match command {
        CanaryCommands::Plant {
            canary_type,
            location,
        } => {
            let canary_type = match canary_type {
                CliCanaryType::Aws => CanaryType::AwsCredentials,
                CliCanaryType::Env => CanaryType::EnvFile,
                CliCanaryType::Ssh => CanaryType::SshKey,
                CliCanaryType::Generic => CanaryType::GenericSecret,
            };

            let location = location.unwrap_or_else(|| {
                let default_dir = dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".balerx")
                    .join("canaries");
                default_dir.join(canary_type.default_filename())
            });

            let canary = manager.plant(canary_type, &location)?;
            println!("\n✓ Canary ID: {}", canary.id);
            println!("\nWARNING: This is a FAKE credential for detection only.");
            println!("If an AI agent accesses this file, Guard will alert immediately.");
        }
        CanaryCommands::Remove { canary_id } => {
            manager.remove(&canary_id)?;
            println!("✓ Canary removed successfully");
        }
        CanaryCommands::List => {
            let canaries = manager.list();

            if canaries.is_empty() {
                println!("No canaries planted yet.");
                println!("\nPlant a canary with: balerx canary plant <type>");
                return Ok(());
            }

            println!("Planted canaries:\n");
            for canary in canaries {
                println!("┌─ {} [{}]", canary.id, canary.canary_type.name());
                println!("│  Location: {}", canary.location.display());
                println!("│  Created: {}", canary.created_at);
                println!("└─ {}\n", canary.description);
            }
        }
        CanaryCommands::Check { path } => {
            if let Some(canary) = manager.is_canary(&path) {
                println!("⚠ This is a CANARY credential!");
                println!("ID: {}", canary.id);
                println!("Type: {}", canary.canary_type.name());
                println!("Created: {}", canary.created_at);
            } else {
                println!("✓ Not a canary - this is a regular file");
            }
        }
    }

    Ok(())
}

fn default_policy_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".balerx")
        .join("policy.yaml")
}

fn require_remote_credentials(
    api_url: Option<String>,
    api_key: Option<String>,
) -> Result<(String, String)> {
    let api_url = api_url
        .or_else(|| std::env::var("BALERX_API_URL").ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Pass --api-url or set BALERX_API_URL. The CLI stays offline until you opt in."
            )
        })?;
    let api_key = api_key
        .or_else(|| std::env::var("BALERX_API_KEY").ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Pass --api-key or set BALERX_API_KEY. The CLI stays offline until you opt in."
            )
        })?;
    Ok((api_url, api_key))
}

fn guard_hooks_installed(home: &std::path::Path) -> bool {
    [
        home.join(".cursor").join("hooks.json"),
        home.join(".claude").join("settings.json"),
    ]
    .into_iter()
    .any(|path| std::fs::read_to_string(path).is_ok_and(|text| text.contains("balerx")))
}

fn drift_json(drift: &DriftType) -> serde_json::Value {
    let (kind, server, agent) = match drift {
        DriftType::NewAgent(_) => ("new_agent", None, None),
        DriftType::RemovedAgent(_) => ("removed_agent", None, None),
        DriftType::AgentVersionChanged { .. } => ("agent_version_changed", None, None),
        DriftType::NewMcpServer { server, agent } => (
            "new_mcp_server",
            Some(server.as_str()),
            Some(agent.as_str()),
        ),
        DriftType::RemovedMcpServer { server, agent } => (
            "removed_mcp_server",
            Some(server.as_str()),
            Some(agent.as_str()),
        ),
        DriftType::McpVersionChanged { server, .. } => {
            ("mcp_version_changed", Some(server.as_str()), None)
        }
        DriftType::McpCommandChanged { server, .. } => {
            ("mcp_command_changed", Some(server.as_str()), None)
        }
        DriftType::McpArgsChanged { server } => ("mcp_args_changed", Some(server.as_str()), None),
        DriftType::ConfigHashChanged { agent } => {
            ("config_hash_changed", None, Some(agent.as_str()))
        }
        DriftType::AutoApproveChanged { agent, .. } => {
            ("auto_approve_changed", None, Some(agent.as_str()))
        }
        DriftType::HooksDisabled { agent } => ("hooks_disabled", None, Some(agent.as_str())),
    };
    serde_json::json!({
        "kind": kind,
        "message": drift.message(),
        "server": server,
        "agent": agent,
    })
}

fn install_policy_yaml(yaml: &str, path: &std::path::Path) -> Result<()> {
    let policy = Policy::from_yaml_str(yaml)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    policy.to_file(path)
}

fn run_policy_pull(
    api_url: Option<String>,
    api_key: Option<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    let (api_url, api_key) = require_remote_credentials(api_url, api_key)?;
    let base = api_url.trim_end_matches('/');
    let mut response = ureq::get(&format!("{base}/v1/ingest/policy"))
        .header("Authorization", format!("Bearer {api_key}"))
        .call()
        .map_err(|error| anyhow::anyhow!("Policy pull failed: {error}"))?;
    let yaml = response
        .body_mut()
        .read_to_string()
        .context("Failed to read organization policy")?;
    let path = output.unwrap_or_else(default_policy_path);
    install_policy_yaml(&yaml, &path)?;
    println!("Wrote organization policy to {}", path.display());
    Ok(())
}

fn nonempty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}

fn json_string(input: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        input
            .get(*key)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn machine_name() -> String {
    if let Ok(name) = hostname::get() {
        if let Ok(text) = name.into_string() {
            if !text.is_empty() {
                return text;
            }
        }
    }
    nonempty_env("HOSTNAME")
        .or_else(|| nonempty_env("COMPUTERNAME"))
        .unwrap_or_else(|| "unknown".to_string())
}

fn guard_activity_metadata(
    input: &serde_json::Value,
    extra: &serde_json::Value,
) -> serde_json::Value {
    let mut context = serde_json::Map::new();
    context.insert("machine".to_string(), serde_json::json!(machine_name()));
    context.insert("os".to_string(), serde_json::json!(std::env::consts::OS));
    if let Some(user) = json_string(input, &["user", "username"])
        .or_else(|| nonempty_env("USER"))
        .or_else(|| nonempty_env("USERNAME"))
    {
        context.insert("user".to_string(), serde_json::Value::String(user));
    }
    let cwd = json_string(input, &["cwd", "working_directory", "workingDirectory"]).or_else(|| {
        std::env::current_dir()
            .ok()
            .and_then(|path| path.into_os_string().into_string().ok())
    });
    if let Some(cwd) = cwd {
        context.insert("cwd".to_string(), serde_json::Value::String(cwd));
    }
    if let Some(object) = extra.as_object() {
        for (key, value) in object {
            context.insert(key.clone(), value.clone());
        }
    }
    serde_json::Value::Object(context)
}

fn hostname_label() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn chrono_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

fn attach_fleet(payload: &mut serde_json::Value, lockfile: Option<&PathBuf>) -> Result<()> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let mut drift = Vec::new();
    let mut mcp_servers = Vec::new();
    if let Some(path) = lockfile {
        let saved = Lockfile::from_file(path)?;
        let current = discovered_lockfile();
        for item in saved.diff(&current) {
            if let DriftType::NewMcpServer { server, .. } = &item {
                mcp_servers.push(server.clone());
            }
            drift.push(drift_json(&item));
        }
        for server in current.mcp_servers {
            mcp_servers.push(server.name);
        }
    }
    if let Some(object) = payload.as_object_mut() {
        object.insert(
            "fleet".to_string(),
            serde_json::json!({
                "drift": drift,
                "guard_hooks_installed": guard_hooks_installed(&home),
                "mcp_servers": mcp_servers,
            }),
        );
    }
    Ok(())
}

fn run_upload(
    api_url: Option<String>,
    api_key: Option<String>,
    scan: Option<&PathBuf>,
    activity_log: Option<PathBuf>,
    lockfile: Option<&PathBuf>,
) -> Result<()> {
    let (api_url, api_key) = require_remote_credentials(api_url, api_key)?;

    if scan.is_none() && activity_log.is_none() && lockfile.is_none() {
        anyhow::bail!("Provide --scan, --activity-log, and/or --lockfile");
    }

    let base = api_url.trim_end_matches('/');
    if scan.is_some() || lockfile.is_some() {
        let mut payload = if let Some(path) = &scan {
            serde_json::from_str(&std::fs::read_to_string(path)?)?
        } else {
            serde_json::json!({
                "scan_id": format!("drift-{}", chrono_millis()),
                "device": { "hostname": hostname_label() },
                "summary": {},
                "agents": [],
                "findings": []
            })
        };
        attach_fleet(&mut payload, lockfile)?;
        post_json(&format!("{base}/v1/ingest/scans"), &api_key, &payload)?;
        if let Some(path) = &scan {
            println!("Uploaded scan {}", path.display());
        } else {
            println!("Uploaded lockfile drift");
        }
    }

    if let Some(path) = activity_log {
        let events = metadata_activity_events(&std::fs::read_to_string(&path)?)?;
        post_json(
            &format!("{base}/v1/ingest/activity"),
            &api_key,
            &serde_json::json!({ "events": events }),
        )?;
        println!(
            "Uploaded {} activity events from {}",
            events.len(),
            path.display()
        );
    }

    Ok(())
}

fn metadata_activity_events(contents: &str) -> Result<Vec<serde_json::Value>> {
    let mut events = Vec::new();
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut event: serde_json::Value = serde_json::from_str(line)?;
        if let Some(object) = event.as_object_mut() {
            object.remove("tool_args");
        }
        events.push(event);
    }
    Ok(events)
}

fn post_json(url: &str, api_key: &str, payload: &serde_json::Value) -> Result<()> {
    ureq::post(url)
        .header("Authorization", format!("Bearer {api_key}"))
        .send_json(payload)
        .map_err(|error| anyhow::anyhow!("Upload failed: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod upload_tests {
    use super::{
        guard_activity_metadata, guard_hooks_installed, install_policy_yaml,
        metadata_activity_events,
    };
    use std::fs;

    #[test]
    fn activity_metadata_keeps_endpoint_context() {
        let input = serde_json::json!({
            "cwd": "/Users/demo/acme",
            "user": "demo",
            "command": "pwd"
        });
        let metadata = guard_activity_metadata(
            &input,
            &serde_json::json!({ "matched_rule": "deny_env_files" }),
        );
        assert_eq!(metadata["cwd"], "/Users/demo/acme");
        assert_eq!(metadata["user"], "demo");
        assert_eq!(metadata["os"], std::env::consts::OS);
        assert_eq!(metadata["matched_rule"], "deny_env_files");
        assert!(metadata["machine"]
            .as_str()
            .is_some_and(|name| !name.is_empty()));
    }

    #[test]
    fn drops_tool_arguments_before_upload() {
        let input = r#"{"event_type":"tool","action":"read","tool_args":{"secret":"x"}}
{"event_type":"decision","decision":"allow"}
"#;
        let events = metadata_activity_events(input).expect("parse activity log");
        assert_eq!(events.len(), 2);
        assert!(events[0].get("tool_args").is_none());
        assert_eq!(events[0]["action"], "read");
        assert_eq!(events[1]["decision"], "allow");
    }

    #[test]
    fn invalid_policy_yaml_is_not_written() {
        let path =
            std::env::temp_dir().join(format!("balerx-policy-invalid-{}", std::process::id()));
        let error = install_policy_yaml("version: [\n", &path);
        assert!(error.is_err());
        assert!(!path.exists());
    }

    #[test]
    fn writes_a_valid_organization_policy() {
        let path = std::env::temp_dir().join(format!("balerx-policy-valid-{}", std::process::id()));
        let yaml = r#"
version: "1.0.0"
global:
  fail_open: true
  timeout_ms: 50
rules: []
"#;
        install_policy_yaml(yaml, &path).expect("write policy");
        let saved = fs::read_to_string(&path).expect("read policy");
        assert!(saved.contains("version"));
        fs::remove_file(path).expect("remove policy");
    }

    #[test]
    fn guard_hook_marker_is_local_only() {
        let dir = std::env::temp_dir().join(format!("balerx-hooks-{}", std::process::id()));
        fs::create_dir_all(dir.join(".cursor")).expect("mkdir");
        fs::write(
            dir.join(".cursor").join("hooks.json"),
            r#"{"command":"other"}"#,
        )
        .expect("write hooks");
        assert!(!guard_hooks_installed(&dir));
        fs::write(
            dir.join(".cursor").join("hooks.json"),
            r#"{"command":"balerx"}"#,
        )
        .expect("write balerx hooks");
        assert!(guard_hooks_installed(&dir));
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
