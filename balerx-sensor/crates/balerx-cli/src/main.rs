use anyhow::{Context, Result};
use balerx_core::{
    canary::{CanaryManager, CanaryType},
    config::ConfigIssue,
    config::IssueType,
    discovery::{AgentDiscovery, ConfigScanner},
    finding::{Confidence, Finding, FindingSeverity, ScanResult},
    guard::{AgentType, HookInstaller},
    hook_input::{
        decide_invalid_policy, decide_oversized, decide_payload, decide_timeout, decide_unreadable,
        is_fail_open_allow, MAX_HOOK_INPUT_BYTES,
    },
    lockfile::{DriftType, Lockfile},
    log::{ActivityEvent, ActivityLog},
    output::{terminal, write_html, write_json, write_sarif},
    poison::PoisonDetector,
    policy::{Policy, PolicyFile},
    process::ProcessCollector,
    rules::RuleId,
};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use std::io::{self, BufRead, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tracing::info;

mod banner;
mod setup;
mod uninstall;
mod update_check;

#[derive(Parser)]
#[command(name = "balerx")]
#[command(about = "Balerx Gate - Security scanner for AI coding agents", long_about = None)]
#[command(version)]
#[command(after_help = "Common commands:
  balerx scan
  balerx setup
  balerx guard install claude-code
  balerx guard install cursor
  balerx guard status
  balerx uninstall
  balerx doctor
  balerx self-update --check

Docs: https://balerxgate.com/docs/cli")]
struct Cli {
    /// Disable color. Same as setting `NO_COLOR`.
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan the system for AI agents and security issues
    Scan {
        /// Project directory or a single config file to scan
        path: Option<PathBuf>,

        /// Write the report to stdout as json, sarif, or text
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,

        /// Exit 1 when a finding is at or above this severity
        #[arg(long, value_enum, value_name = "SEVERITY")]
        fail_on: Option<FailOn>,

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

        /// Skip findings under this path. Repeat the flag to skip more than one.
        #[arg(long, value_name = "PATH")]
        exclude: Vec<PathBuf>,

        /// JSON file of findings to hide. Shape: `{"ignore":[{"rule_id":"...","resource":"..."}]}`
        #[arg(long, value_name = "FILE")]
        baseline: Option<PathBuf>,
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

    /// Remove Guard hooks for Claude Code and Cursor. Offline.
    ///
    /// Deletes only Balerx hook commands from Claude Code and Cursor. A command matches when it contains `balerx` and `hook` and a token names `balerx` or `balerx.exe` with a separate `hook` argument. Other hooks stay. Empty hook lists left by those commands are removed.
    /// Without `--purge`, policy files and the activity log stay, and the command says so.
    /// `--purge` deletes known files only: `policy.yaml`, `policy.yaml.bak` copies, planted canary files in `~/.balerx/canaries`, `canaries.json`, and `logs/activity.jsonl`. Unknown files stay. A directory is removed only when it is empty afterward and its name is `.balerx` or `balerx`. A custom data directory is never removed wholesale.
    /// The command prints every path and asks before it changes anything.
    /// `--yes` skips the question. When stdin is not a terminal and `--yes` is absent, nothing is removed.
    /// Purge stops without deleting anything when the home directory or the data directory is not an absolute path.
    /// On macOS and Linux, `$HOME/.local/bin/balerx` is removed only when that file is the running binary.
    /// On Windows, purge deletes known data files and does not delete `balerx.exe`. The command prints the PowerShell that deletes `%LOCALAPPDATA%\balerx` and that folder's user Path entry.
    Uninstall(uninstall::UninstallArgs),

    /// Hook handler (called by agent hooks)
    ///
    /// Reads at most 1 MB of stdin. A larger body returns ask.
    /// A missing policy file uses the built-in default. An empty or unreadable
    /// policy file fails closed with ask. `timeout_ms` starts at process start
    /// and is checked after stdin closes. A stdin that never closes can still
    /// hang. `fail_open` chooses allow or deny after a timeout or invalid JSON,
    /// and that allow is written to the activity log and stderr.
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

        /// Project ingest API key (hashed at rest on the server).
        /// Pass "-" to read from stdin, or set `BALERX_API_KEY`.
        /// A literal value is rejected for security.
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

    /// Choose a local Guard policy and write ~/.balerx/policy.yaml. Offline.
    ///
    /// A terminal shows a checklist. Arrow keys move, space toggles, and enter confirms.
    /// `--yes` writes the balanced preset. `--preset strict|balanced|minimal` writes that preset.
    /// When stdin is not a terminal, the balanced preset is written and this command does not prompt.
    /// `--yes` and `--preset` leave an existing file in place. Pass `--replace` to copy it to `policy.yaml.bak` and write a new file.
    /// A checklist confirms before it replaces an existing file. The previous file is copied to `policy.yaml.bak`.
    Setup(setup::SetupArgs),

    /// Manage the local Guard policy. Offline unless you explicitly pull.
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },

    /// Show version, data directory, Guard hooks, and policy. Parses the policy file. Empty or invalid YAML exits 1. Does not use the network.
    Doctor,

    /// Print a shell completion script
    Completions {
        /// bash, zsh, fish, or powershell
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Print this version.
    ///
    /// `--check` makes a single request to the public GitHub releases API.
    /// Every other command stays offline except `upload` and `policy pull`.
    /// `balerx --version` and `-V` stay offline and do not accept `--check`.
    Version {
        /// Check GitHub for a newer release. Opt-in: nothing is checked unless you ask.
        ///
        /// Makes a single request to the public GitHub releases API.
        /// Every other command stays offline except `upload` and `policy pull`.
        /// A timeout, rate limit, or missing network prints a message and exits 0.
        #[arg(long)]
        check: bool,

        /// Print JSON. With `--check`, include the release comparison. Without it, print this version only.
        #[arg(long)]
        json: bool,
    },

    /// Print the install command.
    ///
    /// Without `--check`, this prints the install command and does not download or replace the binary.
    /// `--check` makes a single request to the public GitHub releases API.
    /// Every other command stays offline except `upload` and `policy pull`.
    SelfUpdate {
        /// Check GitHub for a newer release. Opt-in: nothing is checked unless you ask.
        ///
        /// Makes a single request to the public GitHub releases API.
        /// Every other command stays offline except `upload` and `policy pull`.
        /// A timeout, rate limit, or missing network prints a message and exits 0.
        #[arg(long)]
        check: bool,

        /// Print the check result as JSON. Requires `--check`.
        #[arg(long, requires = "check")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Same as `balerx setup`.
    Init(setup::SetupArgs),

    /// Print the active policy. The built-in policy is shown when no file exists.
    Show,

    /// Open the checklist again, pre-filled from the current policy file.
    ///
    /// `--preset` or `--yes` rewrites the file without a terminal. The previous file is copied to `policy.yaml.bak`.
    /// `global.fail_open` and `global.timeout_ms` are kept from the current file.
    Edit(setup::SetupArgs),

    /// Fetch the organization policy with an ingest key and write it locally.
    ///
    /// Does not contact the network unless `--api-url` and `BALERX_API_KEY` are set,
    /// or `--api-key -` is passed to read from stdin.
    Pull {
        /// API base URL from your Balerx Gate dashboard onboarding.
        /// No host is compiled in. Overrides `BALERX_API_URL` when set.
        #[arg(long)]
        api_url: Option<String>,

        /// Project ingest or enrollment API key.
        /// Pass "-" to read from stdin, or set `BALERX_API_KEY`.
        /// A literal value is rejected for security.
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
        #[arg(value_enum, ignore_case = true)]
        agent: CliAgentType,
    },

    /// Uninstall guard hooks for an agent
    Uninstall {
        /// Agent type to uninstall hooks for
        #[arg(value_enum, ignore_case = true)]
        agent: CliAgentType,
    },

    /// Show whether Guard hooks are installed
    Status {
        /// Exit 1 when no hook is installed
        #[arg(long, visible_alias = "check")]
        strict: bool,
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
    /// Plant a canary credential. Refuses to overwrite an existing file unless --force is passed. Symbolic links and symlinked parent directories are always refused, even with --force
    Plant {
        /// Type of canary to plant
        #[arg(value_enum)]
        canary_type: CliCanaryType,

        /// Location to plant the canary
        #[arg(short, long)]
        location: Option<PathBuf>,

        /// Overwrite existing file if it exists. Symbolic links and symlinked parent directories are always refused, even with --force
        #[arg(short, long)]
        force: bool,
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
    #[value(alias = "claude_code")]
    ClaudeCode,
    Cursor,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Json,
    Sarif,
    Text,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FailOn {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliCanaryType {
    Aws,
    Env,
    Ssh,
    Generic,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Shell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

fn lists_agent_values_on_extra_word(error: &clap::Error) -> bool {
    if error.kind() != clap::error::ErrorKind::UnknownArgument {
        return false;
    }
    let mut saw_guard = false;
    let mut saw_action = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "guard" => saw_guard = true,
            "install" | "uninstall" => saw_action = true,
            _ => {}
        }
    }
    saw_guard && saw_action
}

struct ScanOptions {
    path: Option<PathBuf>,
    format: Option<OutputFormat>,
    fail_on: Option<FailOn>,
    json: Option<PathBuf>,
    sarif: Option<PathBuf>,
    html: Option<PathBuf>,
    quiet: bool,
    exclude: Vec<PathBuf>,
    baseline: Option<PathBuf>,
}

fn parse_cli() -> Cli {
    match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if lists_agent_values_on_extra_word(&error) {
                let rendered = error.to_string();
                eprint!("{rendered}");
                if !rendered.to_ascii_lowercase().contains("possible values") {
                    eprintln!("  [possible values: claude-code, cursor]");
                }
                std::process::exit(2);
            }
            error.exit();
        }
    }
}

fn main() -> Result<()> {
    let cli = parse_cli();
    let quiet = std::env::args().any(|arg| arg == "-q" || arg == "--quiet");
    let no_color = cli.no_color || terminal::no_color();
    let filter = if quiet {
        tracing_subscriber::EnvFilter::new("off")
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .with_writer(std::io::stderr)
        .with_ansi(!no_color && std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();

    match cli.command {
        Commands::Scan {
            path,
            format,
            fail_on,
            json,
            sarif,
            html,
            quiet,
            exclude,
            baseline,
        } => {
            run_scan(ScanOptions {
                path,
                format,
                fail_on,
                json,
                sarif,
                html,
                quiet,
                exclude,
                baseline,
            })?;
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
        Commands::Uninstall(args) => {
            uninstall::run(&args, no_color)?;
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
        Commands::Setup(args) => {
            setup::run(&args, no_color, setup::Mode::Create)?;
        }
        Commands::Policy { command } => {
            dispatch_policy(command, no_color)?;
        }
        Commands::Doctor => {
            run_doctor()?;
        }
        Commands::Completions { shell } => {
            print_completions(shell);
        }
        Commands::Version { check, json } => update_check::run_version(check, json),
        Commands::SelfUpdate { check, json } => update_check::run_self_update(check, json),
    }

    Ok(())
}

fn dispatch_policy(command: PolicyCommands, no_color: bool) -> Result<()> {
    match command {
        PolicyCommands::Init(args) => setup::run(&args, no_color, setup::Mode::Create),
        PolicyCommands::Show => setup::show(),
        PolicyCommands::Edit(args) => setup::run(&args, no_color, setup::Mode::Edit),
        PolicyCommands::Pull {
            api_url,
            api_key,
            output,
        } => run_policy_pull(api_url, api_key, output),
    }
}

// Main scan orchestration: length is acceptable for sequential workflow
#[allow(clippy::too_many_lines)]
fn run_scan(options: ScanOptions) -> Result<()> {
    let ScanOptions {
        path: scan_path,
        format,
        fail_on,
        json: json_path,
        sarif: sarif_path,
        html: html_path,
        quiet,
        exclude,
        baseline,
    } = options;
    let scan_path = scan_path.as_deref();
    info!("Starting Balerx Gate security scan");

    let mut result = ScanResult::new();

    let discovery = AgentDiscovery::new();
    let agents = if scan_path.as_ref().is_some_and(|path| path.is_file()) {
        Vec::new()
    } else {
        discovery.discover_all()
    };

    for agent in agents {
        result.add_agent(agent);
    }

    let config_scanner = ConfigScanner::new()?;

    let mut agent_configs: Vec<_> = result
        .agents
        .iter()
        .flat_map(|agent| {
            agent
                .config_paths
                .iter()
                .map(move |path| (agent.name.clone(), path.clone()))
        })
        .collect();

    if let Some(path) = &scan_path {
        if path.is_file() {
            agent_configs.push(("path".to_string(), path.to_path_buf()));
        } else if path.is_dir() {
            for relative in [
                ".mcp.json",
                ".cursor/mcp.json",
                ".vscode/mcp.json",
                ".claude/settings.json",
                ".claude.json",
            ] {
                let candidate = path.join(relative);
                if candidate.is_file() {
                    agent_configs.push((relative.to_string(), candidate));
                }
            }
        } else {
            anyhow::bail!("Scan path not found: {}", path.display());
        }
    }

    for (agent_name, config_path) in agent_configs {
        info!("Scanning config: {:?}", config_path);

        match config_scanner.scan_config(&config_path) {
            Ok(scan_result) => {
                for secret in scan_result.secrets_found {
                    let mut finding = Finding::new(
                        secret_rule(&secret.location),
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
                    .with_evidence(&serde_json::json!({
                        "redacted_value": secret.redacted_value,
                        "location": secret.location
                    }))
                    .with_fix("Move this secret to a secure credential store (OS keychain, environment variable, or vault)");
                    if let Some(line) = secret.line {
                        finding = finding.with_line(line);
                    }

                    result.add_finding(finding);
                }

                for issue in scan_result.issues {
                    let (severity, rule_id, fix) = map_config_issue(&issue, &config_path);

                    let mut finding = Finding::new(
                        rule_id,
                        severity,
                        issue.description.clone(),
                        "MCP server configuration issue detected".to_string(),
                    )
                    .with_agent(&agent_name)
                    .with_resource(config_path.to_string_lossy().to_string())
                    .with_evidence(&serde_json::json!({
                        "server_name": issue.server_name,
                        "resource": issue.resource
                    }))
                    .with_fix(fix)
                    .with_confidence(Confidence::High);
                    if let Some(line) = issue.line {
                        finding = finding.with_line(line);
                    }

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
        for agent in &mut result.agents {
            let names = [
                agent.name.to_ascii_lowercase(),
                agent.definition_id.to_ascii_lowercase(),
            ];
            if names
                .iter()
                .any(|name| balerx_core::process::process_name_matches(&process.name, name))
            {
                agent.process_id = Some(process.pid);
                agent.status = balerx_core::AgentStatus::Running;
            }
        }
    }

    for agent in result.agents.clone() {
        if matches!(agent.definition_id.as_str(), "claude-code" | "cursor")
            && !agent.config_paths.is_empty()
            && !agent.config_paths.iter().any(|path| {
                std::fs::read_to_string(path).is_ok_and(|text| {
                    text.to_ascii_lowercase().contains("balerx")
                        && text.to_ascii_lowercase().contains("hook")
                })
            })
        {
            if let Some(fix) = balerx_core::rules::hook_gap_install_fix(&agent.definition_id) {
                result.add_finding(
                    Finding::new(
                        RuleId::HookGapNoGuard,
                        FindingSeverity::Medium,
                        format!("Guard hooks are not installed for {}", agent.name),
                        "This agent has a config file and no Balerx hook entry".to_string(),
                    )
                    .with_agent(&agent.name)
                    .with_resource(
                        agent
                            .config_paths
                            .first()
                            .map(|path| path.display().to_string())
                            .unwrap_or_default(),
                    )
                    .with_fix(fix),
                );
            }
        }
    }

    let poison_detector = PoisonDetector::new()?;
    let poison_root = scan_path
        .filter(|path| path.is_dir())
        .map(std::path::Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok());
    if let Some(current_dir) = poison_root {
        if let Ok(poison_matches) = poison_detector.scan_directory(&current_dir) {
            for poison in poison_matches {
                let rule = if poison.pattern_name == "Data Exfiltration" {
                    RuleId::ToolPoisonExfiltration
                } else {
                    RuleId::ToolPoisonHiddenInstructions
                };
                let mut finding = Finding::new(
                    rule,
                    match poison.severity {
                        balerx_core::poison::PoisonSeverity::Critical => FindingSeverity::Critical,
                        balerx_core::poison::PoisonSeverity::High => FindingSeverity::High,
                        balerx_core::poison::PoisonSeverity::Medium => FindingSeverity::Medium,
                    },
                    format!("Suspicious instruction detected: {}", poison.pattern_name),
                    "Found potentially malicious pattern in agent configuration file".to_string(),
                )
                .with_resource(poison.location.clone())
                .with_evidence(&serde_json::json!({
                    "pattern": poison.pattern_name,
                    "context": poison.context
                }))
                .with_fix("Review this instruction and remove it if it was not intentionally added")
                .with_confidence(Confidence::Medium)
                .with_line(poison.line);
                if let Some(agent) = balerx_core::poison::agent_for_path(&poison.location) {
                    finding = finding.with_agent(agent);
                }

                result.add_finding(finding);
            }
        }
    }

    apply_scan_filters(&mut result, &exclude, baseline.as_deref())?;

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

    match format {
        Some(OutputFormat::Json) => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Some(OutputFormat::Sarif) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&balerx_core::output::sarif::to_sarif(&result))?
            );
        }
        Some(OutputFormat::Text) => terminal::print_scan_result(&result),
        None if !quiet => terminal::print_scan_result(&result),
        None => {}
    }

    info!("Scan complete");

    if !quiet && setup::policy_missing() {
        eprintln!("{}", setup::POLICY_HINT);
    }

    let code = exit_code(&result, fail_on);
    if code != 0 {
        std::process::exit(code);
    }

    Ok(())
}

fn exit_code(result: &ScanResult, fail_on: Option<FailOn>) -> i32 {
    if let Some(level) = fail_on {
        let hit = result
            .findings
            .iter()
            .any(|finding| severity_rank(finding.severity) >= fail_rank(level));
        return i32::from(hit);
    }
    if result.summary.critical_count > 0 {
        return 2;
    }
    i32::from(result.summary.high_count > 0)
}

fn severity_rank(severity: FindingSeverity) -> u8 {
    match severity {
        FindingSeverity::Critical => 5,
        FindingSeverity::High => 4,
        FindingSeverity::Medium => 3,
        FindingSeverity::Low => 2,
        FindingSeverity::Info => 1,
    }
}

fn fail_rank(level: FailOn) -> u8 {
    match level {
        FailOn::Critical => 5,
        FailOn::High => 4,
        FailOn::Medium => 3,
        FailOn::Low => 2,
        FailOn::Info => 1,
    }
}

fn secret_rule(location: &str) -> RuleId {
    let parts: Vec<&str> = location.split(['.', '[', ']']).collect();
    if parts
        .iter()
        .any(|part| part.eq_ignore_ascii_case("env") || part.eq_ignore_ascii_case("environment"))
    {
        RuleId::SecretInEnv
    } else if parts
        .iter()
        .any(|part| part.eq_ignore_ascii_case("args") || part.eq_ignore_ascii_case("arguments"))
    {
        RuleId::SecretInArgs
    } else {
        RuleId::SecretInConfig
    }
}

fn map_config_issue(issue: &ConfigIssue, config_path: &Path) -> (FindingSeverity, RuleId, String) {
    match issue.issue_type {
        IssueType::UnpinnedPackage => (
            FindingSeverity::Medium,
            RuleId::McpSupplyUnpinned,
            "Pin the package to a specific version, for example package@1.2.3".to_string(),
        ),
        IssueType::LatestTag => (
            FindingSeverity::Medium,
            RuleId::McpSupplyLatest,
            "Replace @latest with a specific version number".to_string(),
        ),
        IssueType::PlainHttp => (
            FindingSeverity::High,
            RuleId::McpRemotePlainHttp,
            "Use HTTPS instead of plain HTTP for remote connections".to_string(),
        ),
        IssueType::BroadFilesystem => (
            FindingSeverity::High,
            RuleId::McpPermBroadFilesystem,
            "Restrict filesystem access to specific directories needed by the tool".to_string(),
        ),
        IssueType::NoAuth => (
            FindingSeverity::Medium,
            RuleId::McpRemoteNoAuth,
            "Add authentication credentials for remote MCP server connections".to_string(),
        ),
        IssueType::BrokenConfig => (
            FindingSeverity::High,
            RuleId::ConfigInvalid,
            "Fix the JSON or TOML syntax so the scanner can read the file".to_string(),
        ),
        IssueType::EmptyConfig => (
            FindingSeverity::Info,
            RuleId::ConfigInvalid,
            empty_config_fix(config_path),
        ),
        IssueType::DockerPrivileged | IssueType::RootMount => (
            FindingSeverity::High,
            RuleId::McpPermDocker,
            "Drop --privileged and host root mounts from the container command".to_string(),
        ),
        IssueType::AutoApprove => (
            FindingSeverity::High,
            RuleId::AgentAutonomyAutoApprove,
            "Turn off approval_policy never or an equivalent auto-approve setting".to_string(),
        ),
        IssueType::DangerousPermissions => (
            FindingSeverity::High,
            RuleId::AgentAutonomyDangerousPermissions,
            "Remove bypassPermissions, Bash(*), or danger-full-access".to_string(),
        ),
        IssueType::ShellExec => (
            FindingSeverity::High,
            RuleId::McpPermShellExec,
            "Replace the shell command with the specific tool binary".to_string(),
        ),
        IssueType::DatabaseAccess => (
            FindingSeverity::Medium,
            RuleId::McpPermDatabase,
            "Use a read-only role and a database that is not production".to_string(),
        ),
    }
}

fn empty_config_fix(path: &Path) -> String {
    let norm = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let body = if extension_is(path, "toml") {
        "Delete the file or add a [mcp_servers.<name>] entry. An empty table is [mcp_servers]."
    } else if extension_is(path, "yml") || extension_is(path, "yaml") {
        yaml_empty_fix(&norm)
    } else if name == "mcp.json" && vscode_mcp_path(&norm) {
        r#"Delete the file or add valid contents, for example { "servers": {} } for VS Code mcp.json."#
    } else if name == "settings.json" && vscode_user_settings(&norm) {
        "Delete the file or add a VS Code settings object, for example {}."
    } else if name == "hooks.json" && norm.contains(".cursor/") {
        r#"Delete the file or add a Cursor hooks file, for example { "version": 1, "hooks": {} }."#
    } else if name == "settings.json" && norm.contains(".claude/settings.json") {
        "Delete the file or add a Claude Code settings object, for example {}."
    } else if name == "settings.json" && norm.contains("zed/settings.json") {
        r#"Delete the file or add a Zed settings object, for example { "context_servers": {} }."#
    } else if name == "config.json" && norm.contains("continue") {
        r#"Delete the file or add a Continue config, for example { "mcpServers": {} }."#
    } else {
        r#"Delete the file or add valid contents, for example { "mcpServers": {} } for Cursor, Claude, Windsurf, Cline, Roo, Gemini, or another JSON MCP config."#
    };
    format!("{body} Nothing was scanned from this file.")
}

fn extension_is(path: &Path, ext: &str) -> bool {
    path.extension()
        .is_some_and(|value| value.eq_ignore_ascii_case(ext))
}

fn yaml_empty_fix(norm: &str) -> &'static str {
    if norm.contains("aider") {
        "Delete the file or add an Aider YAML config. Aider does not use a JSON mcpServers object."
    } else if norm.contains("goose") {
        "Delete the file or add a Goose YAML config. Goose extensions are YAML, not a JSON mcpServers object."
    } else if norm.contains("continue") {
        "Delete the file or add a Continue YAML config. An MCP server list, when used, is mcpServers:."
    } else {
        "Delete the file or add valid YAML. This file is not a JSON mcpServers object."
    }
}

fn vscode_mcp_path(norm: &str) -> bool {
    norm.contains(".vscode/mcp.json") || norm.contains("code/user/mcp.json")
}

fn vscode_user_settings(norm: &str) -> bool {
    norm.contains("code/user/settings.json")
        && !norm.contains("globalstorage")
        && !norm.contains("roo-cline")
}

fn discovered_lockfile() -> Lockfile {
    let discovery = AgentDiscovery::new();
    Lockfile::capture(&discovery.discover_all())
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

#[allow(clippy::too_many_lines)]
fn run_guard(command: &GuardCommands) -> Result<()> {
    let installer = HookInstaller::new();

    match command {
        GuardCommands::Install { agent } => {
            let agent_type = match agent {
                CliAgentType::ClaudeCode => AgentType::ClaudeCode,
                CliAgentType::Cursor => AgentType::Cursor,
            };

            println!("Installing Guard hooks for {agent_type:?}...");
            let written = installer.install(agent_type)?;
            println!("✓ Guard hooks installed successfully");
            for path in &written {
                println!("  • {}", path.display());
            }
            println!("\nThe hooks will intercept:");
            match agent_type {
                AgentType::ClaudeCode => {
                    println!("  • PreToolUse - before each tool execution");
                    println!("  • PostToolUse - after each tool execution");
                }
                AgentType::Cursor => {
                    println!("  • beforeShellExecution - before shell commands");
                    println!("  • beforeMCPExecution - before MCP tool calls");
                    println!("  • beforeReadFile - before file reads");
                }
            }
            println!("\nPolicy file: ~/.balerx/policy.yaml");
            println!(
                "Activity log: {}",
                ActivityLog::default_log().path().display()
            );
            if setup::policy_missing() {
                eprintln!("{}", setup::POLICY_HINT);
            }
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
        GuardCommands::Status { strict } => {
            let status = installer.status();
            println!(
                "Claude Code user hooks: {} ({})",
                if status.claude_user {
                    "installed"
                } else {
                    "not installed"
                },
                status.claude_settings.display()
            );
            println!(
                "Claude Code project hooks: {}",
                if status.claude_project {
                    "installed"
                } else {
                    "not installed"
                }
            );
            println!(
                "Cursor hooks: {} ({})",
                if status.cursor_user {
                    "installed"
                } else {
                    "not installed"
                },
                status.cursor_hooks.display()
            );
            print_guard_policy_status();
            println!(
                "Activity log: {}",
                ActivityLog::default_log().path().display()
            );
            if !status.claude_user && !status.claude_project && !status.cursor_user {
                println!("Not installed — run: balerx guard install claude-code");
                println!("Not installed — run: balerx guard install cursor");
                if *strict {
                    std::process::exit(1);
                }
            }
            let home = balerx_core::agent::home_dir().unwrap_or_else(|| PathBuf::from("."));
            let issues = balerx_core::guard::hook_binary_issues(&home);
            if !issues.is_empty() {
                for issue in &issues {
                    eprintln!("{issue}");
                }
                anyhow::bail!(
                    "Guard hook binary is missing or not executable. Reinstall with: balerx guard install claude-code or balerx guard install cursor"
                );
            }
        }
    }

    Ok(())
}

fn print_guard_policy_status() {
    let policy_path = policy_path_from_env();
    match &policy_path {
        Some(path) => println!("Policy: {}", path.display()),
        None => println!("Policy: {}", balerx_core::agent::HOME_REQUIRED),
    }
    match Policy::inspect_file(policy_path.as_deref()) {
        PolicyFile::Loaded(policy) => println!(
            "  fail_open={} timeout_ms={}",
            policy.global.fail_open, policy.global.timeout_ms
        ),
        PolicyFile::Missing => {
            let policy = Policy::default_policy();
            println!(
                "  fail_open={} timeout_ms={} (built-in default)",
                policy.global.fail_open, policy.global.timeout_ms
            );
        }
        PolicyFile::Empty { .. } => println!("  policy file is empty; hook fails closed"),
        PolicyFile::Invalid { message, .. } => {
            println!("  policy file is invalid; hook fails closed ({message})");
        }
    }
}

fn hook_policy() -> (Policy, Option<String>) {
    let policy_file = Policy::inspect_file(policy_path_from_env().as_deref());
    match &policy_file {
        PolicyFile::Missing | PolicyFile::Loaded(_) => (loaded_or_default(&policy_file), None),
        PolicyFile::Empty { path } => {
            let reason = format!(
                "Policy file is empty: {}. Failing closed with ask",
                path.display()
            );
            eprintln!("warning: {reason}");
            (Policy::default_policy(), Some(reason))
        }
        PolicyFile::Invalid { path, message } => {
            let reason = format!(
                "Policy file is invalid ({}): {message}. Failing closed with ask",
                path.display()
            );
            eprintln!("warning: {reason}");
            (Policy::default_policy(), Some(reason))
        }
    }
}

fn apply_canary_override(
    outcome: &mut balerx_core::hook_input::HookOutcome,
    input: &serde_json::Value,
) -> Result<()> {
    let canary_manager = CanaryManager::new()?;
    let canary_path = outcome
        .event
        .resource
        .clone()
        .or_else(|| outcome.event.command.clone());
    let Some(resource) = canary_path else {
        return Ok(());
    };
    let Some(canary) = canary_manager.is_canary(&resource) else {
        return Ok(());
    };
    let reason = "Access to a planted canary credential".to_string();
    outcome.decision.action = balerx_core::policy::PolicyAction::Deny;
    outcome.decision.reason.clone_from(&reason);
    outcome.body = match outcome.kind {
        balerx_core::hook_input::HookAgentKind::ClaudeCode => serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason
            }
        })
        .to_string(),
        balerx_core::hook_input::HookAgentKind::Cursor => serde_json::json!({
            "permission": "deny",
            "user_message": reason,
            "agent_message": reason
        })
        .to_string(),
    };
    outcome.exit_code = match outcome.kind {
        balerx_core::hook_input::HookAgentKind::ClaudeCode => 2,
        balerx_core::hook_input::HookAgentKind::Cursor => 0,
    };
    let _ = ActivityLog::default_log().append(
        ActivityEvent::new("canary_access", &outcome.event.agent, "denied")
            .with_resource(resource)
            .with_decision("deny")
            .with_metadata(guard_activity_metadata(
                input,
                &serde_json::json!({
                    "canary_id": canary.id,
                    "canary_type": format!("{:?}", canary.canary_type)
                }),
            )),
    );
    Ok(())
}

fn record_hook_activity(
    event_type: &str,
    outcome: &balerx_core::hook_input::HookOutcome,
    input: &serde_json::Value,
    elapsed: u64,
) {
    let resource = outcome
        .event
        .resource
        .clone()
        .or(outcome.event.command.clone())
        .unwrap_or_default();
    let fail_open_allow = is_fail_open_allow(&outcome.decision);
    if fail_open_allow {
        eprintln!("fail_open: {}", outcome.decision.reason);
    }
    let _ = ActivityLog::default_log().append(
        ActivityEvent::new(event_type, &outcome.event.agent, "evaluated")
            .with_resource(resource)
            .with_decision(format!("{:?}", outcome.decision.action))
            .with_metadata(guard_activity_metadata(
                input,
                &serde_json::json!({
                    "matched_rule": outcome.decision.matched_rule,
                    "elapsed_ms": elapsed,
                    "reason": outcome.decision.reason,
                    "fail_open": fail_open_allow
                }),
            )),
    );
}

fn run_hook(event_type: &str) -> Result<()> {
    let start = Instant::now();
    let (policy, policy_block) = hook_policy();
    let input_bytes = read_hook_stdin()?;
    let mut outcome = if let Some(reason) = policy_block {
        decide_invalid_policy(event_type, &reason)
    } else if input_bytes.oversized {
        decide_oversized(event_type)
    } else {
        evaluate_hook_with_timeout(event_type, &input_bytes.raw, &policy, start)
    };
    let input = serde_json::from_str::<serde_json::Value>(&input_bytes.raw)
        .unwrap_or(serde_json::Value::Null);
    apply_canary_override(&mut outcome, &input)?;
    record_hook_activity(event_type, &outcome, &input, elapsed_ms(start));

    println!("{}", outcome.body);
    if outcome.exit_code != 0 {
        eprintln!("{}", outcome.decision.reason);
    }
    // Exit here so a timed-out evaluation thread cannot keep the hook process
    // alive after the wall-clock decision has already been written.
    std::process::exit(outcome.exit_code);
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
            force,
        } => {
            let canary_type = match canary_type {
                CliCanaryType::Aws => CanaryType::AwsCredentials,
                CliCanaryType::Env => CanaryType::EnvFile,
                CliCanaryType::Ssh => CanaryType::SshKey,
                CliCanaryType::Generic => CanaryType::GenericSecret,
            };

            let location = if let Some(location) = location {
                location
            } else {
                let home = balerx_core::agent::absolute_home_dir()
                    .context(balerx_core::agent::HOME_REQUIRED)?;
                home.join(".balerx")
                    .join("canaries")
                    .join(canary_type.default_filename())
            };

            let canary = manager.plant(canary_type, &location, force)?;
            println!("\n✓ Canary ID: {}", canary.id);
            println!("\nWARNING: This is a FAKE credential for detection only.");
            println!(
                "If an AI agent reads this file, Guard records that access in the local activity log."
            );
            println!("This command does not send an alert.");
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
            if !path.exists() {
                eprintln!("Cannot check {}: file not found", path.display());
                std::process::exit(1);
            }
            if let Some(canary) = manager.is_canary(&path) {
                println!("This path is a planted canary");
                println!("ID: {}", canary.id);
                println!("Type: {}", canary.canary_type.name());
                println!("Created: {}", canary.created_at);
                std::process::exit(2);
            }
            println!("Not a planted canary");
        }
    }

    Ok(())
}

fn default_policy_path() -> Result<PathBuf> {
    let home =
        balerx_core::agent::absolute_home_dir().context(balerx_core::agent::HOME_REQUIRED)?;
    Ok(home.join(".balerx").join("policy.yaml"))
}

fn policy_path_from_env() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("BALERX_POLICY") {
        if !value.is_empty() {
            return Some(PathBuf::from(value));
        }
    }
    default_policy_path().ok()
}

fn require_remote_credentials(
    api_url: Option<String>,
    api_key: Option<String>,
) -> Result<(String, String)> {
    let api_url = api_url
        .or_else(|| std::env::var("BALERX_API_URL").ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Pass --api-url or set BALERX_API_URL. The CLI stays offline until you opt in."
            )
        })?;
    let api_key = resolve_api_key(api_key)?;
    Ok((api_url, api_key))
}

fn resolve_api_key(api_key: Option<String>) -> Result<String> {
    if let Some(value) = api_key {
        if value == "-" {
            let mut line = String::new();
            let mut stdin = io::stdin().lock();
            stdin.read_line(&mut line)?;
            let key = line.trim().to_string();
            if key.is_empty() {
                anyhow::bail!("No API key was provided on stdin");
            }
            return Ok(key);
        }
        anyhow::bail!(
            "--api-key VALUE is not accepted. It would show up in the process list and shell history.\n\
             Use one of these secure forms instead:\n\
             \n\
             bash/zsh:\n\
               export BALERX_API_KEY=<key>\n\
               balerx upload --api-url <URL> --scan scan.json\n\
             \n\
             Or read from stdin:\n\
               printf '%s' \"$BALERX_API_KEY\" | balerx upload --api-url <URL> --api-key - --scan scan.json\n\
             \n\
             PowerShell:\n\
               $env:BALERX_API_KEY = \"<key>\"\n\
               balerx upload --api-url <URL> --scan scan.json\n\
             \n\
             Or:\n\
               \"$env:BALERX_API_KEY\" | balerx upload --api-url <URL> --api-key - --scan scan.json\n\
             \n\
             cmd:\n\
               set BALERX_API_KEY=<key>\n\
               balerx upload --api-url <URL> --scan scan.json"
        );
    }
    std::env::var("BALERX_API_KEY")
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Set BALERX_API_KEY, or pass --api-key - to read the key from stdin. The CLI stays offline until you opt in."
            )
        })
}

fn apply_scan_filters(
    result: &mut ScanResult,
    exclude: &[PathBuf],
    baseline: Option<&std::path::Path>,
) -> Result<()> {
    let ignored = match baseline {
        Some(path) => load_baseline(path)?,
        None => Vec::new(),
    };
    if exclude.is_empty() && ignored.is_empty() {
        return Ok(());
    }
    result.retain_findings(|finding| {
        !resource_excluded(&finding.affected_resource, exclude)
            && !baseline_matches(finding, &ignored)
    });
    Ok(())
}

#[derive(serde::Deserialize)]
struct BaselineFile {
    #[serde(default)]
    ignore: Vec<BaselineItem>,
}

#[derive(serde::Deserialize)]
struct BaselineItem {
    rule_id: String,
    resource: String,
}

fn load_baseline(path: &std::path::Path) -> Result<Vec<BaselineItem>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Could not read file: {}", path.display()))?;
    let parsed: BaselineFile = serde_json::from_str(&text).with_context(|| {
        format!(
            "Could not parse baseline {}. Expected {{\"ignore\":[{{\"rule_id\":\"MCP-REMOTE-001\",\"resource\":\".cursor/mcp.json\"}}]}}",
            path.display()
        )
    })?;
    Ok(parsed.ignore)
}

fn baseline_matches(finding: &Finding, ignored: &[BaselineItem]) -> bool {
    let code = finding.rule_id.code();
    let resource = finding.affected_resource.replace('\\', "/");
    let home = balerx_core::lockfile::home_relative(std::path::Path::new(&resource));
    ignored.iter().any(|item| {
        let rule_ok = item.rule_id.eq_ignore_ascii_case(code);
        let pattern = item.resource.replace('\\', "/");
        rule_ok && paths_same(&resource, &home, &pattern)
    })
}

fn paths_same(resource: &str, home: &str, pattern: &str) -> bool {
    resource == pattern
        || home == pattern
        || resource.ends_with(&format!("/{pattern}"))
        || home.ends_with(&format!("/{pattern}"))
}

fn resource_excluded(resource: &str, excludes: &[PathBuf]) -> bool {
    let resource = resource.replace('\\', "/");
    let cwd = std::env::current_dir().ok();
    excludes.iter().any(|exclude| {
        let raw = exclude.to_string_lossy().replace('\\', "/");
        let raw = raw.trim_end_matches('/').to_string();
        if path_has_prefix(&resource, &raw) {
            return true;
        }
        let Some(cwd) = &cwd else {
            return false;
        };
        let absolute = if exclude.is_absolute() {
            exclude.clone()
        } else {
            cwd.join(exclude)
        };
        let absolute = absolute.to_string_lossy().replace('\\', "/");
        let absolute = absolute.trim_end_matches('/').to_string();
        if path_has_prefix(&resource, &absolute) {
            return true;
        }
        std::path::Path::new(&absolute)
            .canonicalize()
            .is_ok_and(|canon| {
                path_has_prefix(
                    &resource,
                    canon
                        .to_string_lossy()
                        .replace('\\', "/")
                        .trim_end_matches('/'),
                )
            })
    })
}

fn path_has_prefix(path: &str, prefix: &str) -> bool {
    !prefix.is_empty() && (path == prefix || path.starts_with(&format!("{prefix}/")))
}

fn run_doctor() -> Result<()> {
    println!("balerx {}", env!("CARGO_PKG_VERSION"));
    let log_path = ActivityLog::default_log().path().to_path_buf();
    let data_dir = log_path
        .parent()
        .and_then(|path| path.parent())
        .map_or_else(|| log_path.clone(), std::path::Path::to_path_buf);
    let writable = std::fs::create_dir_all(&data_dir).is_ok();
    println!(
        "data directory: {} ({})",
        data_dir.display(),
        if writable { "writable" } else { "not writable" }
    );
    let policy_path = policy_path_from_env();
    let mut policy_failed = false;
    match Policy::inspect_file(policy_path.as_deref()) {
        PolicyFile::Missing => match &policy_path {
            Some(path) => println!("policy: {} (built-in default)", path.display()),
            None => println!(
                "policy: {} (built-in default)",
                balerx_core::agent::HOME_REQUIRED
            ),
        },
        PolicyFile::Loaded(policy) => {
            let path = policy_path.as_ref().map_or_else(
                || balerx_core::agent::HOME_REQUIRED.to_string(),
                |path| path.display().to_string(),
            );
            println!("policy: {path} (valid)");
            println!(
                "  fail_open={} timeout_ms={} (effective)",
                policy.global.fail_open, policy.global.timeout_ms
            );
        }
        PolicyFile::Empty { path } => {
            println!("policy: {} (empty)", path.display());
            eprintln!("warning: policy file is empty");
            policy_failed = true;
        }
        PolicyFile::Invalid { path, message } => {
            println!("policy: {} (invalid)", path.display());
            eprintln!("warning: policy file is invalid: {message}");
            policy_failed = true;
        }
    }
    let status = HookInstaller::new().status();
    println!(
        "guard hooks: claude_user={} claude_project={} cursor={}",
        status.claude_user, status.claude_project, status.cursor_user
    );
    println!(
        "activity log: {}",
        ActivityLog::default_log().path().display()
    );
    println!("offline: doctor does not contact the network");
    if !writable {
        anyhow::bail!("The data directory is not writable");
    }
    let home = balerx_core::agent::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let issues = balerx_core::guard::hook_binary_issues(&home);
    if !issues.is_empty() {
        for issue in &issues {
            eprintln!("{issue}");
        }
        anyhow::bail!(
            "Guard hook binary is missing or not executable. Reinstall with: balerx guard install claude-code or balerx guard install cursor"
        );
    }
    if policy_failed {
        anyhow::bail!("Policy file is empty or invalid");
    }
    Ok(())
}

fn loaded_or_default(file: &PolicyFile) -> Policy {
    match file {
        PolicyFile::Loaded(policy) => policy.clone(),
        _ => Policy::default_policy(),
    }
}

struct HookStdin {
    raw: String,
    oversized: bool,
}

fn read_hook_stdin() -> Result<HookStdin> {
    let mut buf = Vec::new();
    let read = io::stdin()
        .take(MAX_HOOK_INPUT_BYTES.saturating_add(1))
        .read_to_end(&mut buf)?;
    let oversized = u64::try_from(read).unwrap_or(u64::MAX) > MAX_HOOK_INPUT_BYTES;
    let raw = if oversized {
        String::new()
    } else {
        String::from_utf8_lossy(&buf).into_owned()
    };
    Ok(HookStdin { raw, oversized })
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn evaluate_hook_with_timeout(
    event_type: &str,
    raw: &str,
    policy: &Policy,
    start: Instant,
) -> balerx_core::hook_input::HookOutcome {
    let budget = Duration::from_millis(policy.global.timeout_ms);
    if start.elapsed() >= budget {
        return decide_timeout(event_type, policy);
    }
    let remaining = budget.saturating_sub(start.elapsed());
    let parsed = serde_json::from_str::<serde_json::Value>(raw);
    let event_owned = event_type.to_string();
    let policy_owned = policy.clone();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let elapsed = elapsed_ms(start);
        let outcome = match parsed {
            Ok(value) => decide_payload(&event_owned, &value, &policy_owned, elapsed),
            Err(_) => decide_unreadable(&event_owned, &policy_owned),
        };
        let _ = tx.send(outcome);
    });
    match rx.recv_timeout(remaining) {
        Ok(outcome) if start.elapsed() < budget => outcome,
        _ => decide_timeout(event_type, policy),
    }
}

fn print_completions(shell: Shell) {
    let commands = Cli::command()
        .get_subcommands()
        .map(clap::Command::get_name)
        .filter(|name| *name != "help")
        .collect::<Vec<_>>()
        .join(" ");
    match shell {
        Shell::Bash => {
            println!("complete -W \"{commands}\" balerx");
        }
        Shell::Zsh => {
            println!("#compdef balerx");
            println!("compadd {commands}");
        }
        Shell::Fish => {
            println!("complete -c balerx -f -a \"{commands}\"");
        }
        Shell::Powershell => {
            println!("Register-ArgumentCompleter -CommandName balerx -ScriptBlock {{");
            println!("  param($word)");
            println!("  '{commands}'.Split(' ') | Where-Object {{ $_ -like \"$word*\" }}");
            println!("}}");
        }
    }
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
        .map_err(|error| http_failure("Policy pull", &error))?;
    let yaml = response
        .body_mut()
        .read_to_string()
        .context("Failed to read organization policy")?;
    let path = match output {
        Some(path) => path,
        None => default_policy_path()?,
    };
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
    let home = balerx_core::agent::home_dir().unwrap_or_else(|| PathBuf::from("."));
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
            let text = read_user_file(path)?;
            serde_json::from_str(&text)
                .with_context(|| format!("Could not parse JSON in {}", path.display()))?
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
        let redacted_payload = balerx_core::redaction::redact_evidence_value(&payload);
        post_json(
            &format!("{base}/v1/ingest/scans"),
            &api_key,
            &redacted_payload,
        )?;
        if let Some(path) = &scan {
            println!("Uploaded scan {}", path.display());
        } else {
            println!("Uploaded lockfile drift");
        }
    }

    if let Some(path) = activity_log {
        let events = metadata_activity_events(&read_user_file(&path)?)?;
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

fn read_user_file(path: &std::path::Path) -> Result<String> {
    std::fs::read_to_string(path)
        .with_context(|| format!("Could not read file: {}", path.display()))
}

fn http_failure(action: &str, error: &ureq::Error) -> anyhow::Error {
    let text = error.to_string();
    if text.contains("401") {
        anyhow::anyhow!(
            "{action} failed: the server rejected the API key (HTTP 401). Check BALERX_API_KEY."
        )
    } else {
        anyhow::anyhow!("{action} failed: {text}")
    }
}

fn post_json(url: &str, api_key: &str, payload: &serde_json::Value) -> Result<()> {
    ureq::post(url)
        .header("Authorization", format!("Bearer {api_key}"))
        .send_json(payload)
        .map_err(|error| http_failure("Upload", &error))?;
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
