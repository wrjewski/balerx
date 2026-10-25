//! `balerx setup` writes `~/.balerx/policy.yaml` without using the network.

use anyhow::{Context, Result};
use balerx_core::guard::{AgentType, HookInstaller};
use balerx_core::policy::{Condition, Policy, PolicyAction};
use balerx_core::policy_setup::{
    self, choices_from_policy, policy_from_choices, preset_choices, to_yaml, ChecklistItem,
    ItemChoice, SetupPreset,
};
use clap::{Args, ValueEnum};
use dialoguer::theme::{ColorfulTheme, SimpleTheme};
use dialoguer::{Confirm, MultiSelect};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

pub const POLICY_HINT: &str = "No policy set yet. Run: balerx setup";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Create,
    Edit,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliPreset {
    Strict,
    Balanced,
    Minimal,
}

impl From<CliPreset> for SetupPreset {
    fn from(preset: CliPreset) -> Self {
        match preset {
            CliPreset::Strict => SetupPreset::Strict,
            CliPreset::Balanced => SetupPreset::Balanced,
            CliPreset::Minimal => SetupPreset::Minimal,
        }
    }
}

#[derive(Debug, Args, Clone)]
pub struct SetupArgs {
    /// Write strict, balanced, or minimal without the checklist. An existing file requires --replace.
    #[arg(long, value_enum)]
    pub preset: Option<CliPreset>,

    /// Write the balanced preset without prompting. An existing file requires --replace.
    #[arg(long)]
    pub yes: bool,

    /// Replace an existing policy. The current file is copied to policy.yaml.bak first.
    #[arg(long)]
    pub replace: bool,
}

pub fn run(args: &SetupArgs, no_color: bool, mode: Mode) -> Result<()> {
    if mode == Mode::Create {
        crate::banner::print_for_setup(no_color);
    }
    let path = policy_path()?;
    let tty = std::io::stdin().is_terminal();
    let preset = args.preset.map(SetupPreset::from);
    let explicit = args.yes || preset.is_some();
    if mode == Mode::Edit && !tty && !explicit {
        anyhow::bail!(
            "No terminal attached. Run balerx policy edit --preset balanced, or open a terminal."
        );
    }
    if path.is_file() && !may_replace(args, mode, tty, no_color)? {
        eprintln!("A policy already exists at {}.", path.display());
        eprintln!(
            "--yes and --preset do not replace it. --replace is required to copy the file to policy.yaml.bak and write a new one."
        );
        std::process::exit(1);
    }

    let existing = if path.is_file() {
        Some(Policy::from_file(&path).with_context(|| {
            format!(
                "Could not read {}. Fix the YAML or move the file.",
                path.display()
            )
        })?)
    } else {
        None
    };
    let fell_back = !tty && !explicit;
    let policy = if !tty || explicit {
        let preserve = if mode == Mode::Edit {
            existing.as_ref()
        } else {
            None
        };
        policy_from_choices(
            &preset_choices(preset.unwrap_or(SetupPreset::Balanced)),
            preserve,
        )
    } else {
        let choices = match (&existing, mode) {
            (Some(policy), Mode::Edit) => choices_from_policy(policy),
            _ => preset_choices(SetupPreset::Balanced),
        };
        let Some(selected) = prompt_checklist(&choices, no_color)? else {
            println!("Setup cancelled. No policy was written.");
            return Ok(());
        };
        let mut chosen = choices;
        for (index, on) in selected.into_iter().enumerate() {
            if let Some(choice) = chosen.get_mut(index) {
                choice.enabled = on;
            }
        }
        let preserve = if mode == Mode::Edit {
            existing.as_ref()
        } else {
            None
        };
        policy_from_choices(&chosen, preserve)
    };

    if path.is_file() {
        let backup = backup_policy(&path)?;
        println!("Copied the previous policy to {}", backup.display());
    }
    write_policy(&path, &policy)?;
    if fell_back {
        println!("No terminal attached. Wrote the balanced policy.");
    }
    println!("Wrote {}", path.display());
    println!(
        "fail_open is {} and timeout_ms is {}.",
        policy.global.fail_open, policy.global.timeout_ms
    );
    if tty && !explicit {
        for note in policy_setup::unsupported() {
            println!("Not in the checklist: {note}");
        }
    }
    offer_hooks(tty && !explicit, no_color)
}

fn may_replace(args: &SetupArgs, mode: Mode, tty: bool, no_color: bool) -> Result<bool> {
    if args.replace || (mode == Mode::Edit && (args.yes || args.preset.is_some())) {
        return Ok(true);
    }
    if !tty || args.yes || args.preset.is_some() {
        return Ok(false);
    }
    confirm(
        "A policy already exists. Copy it to policy.yaml.bak and replace it?",
        false,
        no_color,
    )
}

pub fn show() -> Result<()> {
    let path = policy_path()?;
    if path.is_file() {
        println!("Policy file: {}", path.display());
        print_policy(&Policy::from_file(&path)?);
    } else {
        println!("{POLICY_HINT}");
        println!("Built-in policy. No file at {}.", path.display());
        print_policy(&Policy::default_policy());
    }
    Ok(())
}

pub fn policy_missing() -> bool {
    match policy_path() {
        Ok(path) => !path.is_file(),
        Err(_) => true,
    }
}

fn print_policy(policy: &Policy) {
    println!("fail_open: {}", policy.global.fail_open);
    println!("timeout_ms: {}", policy.global.timeout_ms);
    for rule in &policy.rules {
        let state = if rule.enabled { "on" } else { "off" };
        println!(
            "[{}] {state} {} — {}",
            action_name(rule.action),
            rule.id,
            rule.description
        );
        for condition in &rule.conditions {
            println!("  {}", condition_line(condition));
        }
    }
}

fn action_name(action: PolicyAction) -> &'static str {
    match action {
        PolicyAction::Allow => "allow",
        PolicyAction::Deny => "deny",
        PolicyAction::Ask => "ask",
    }
}

fn condition_line(condition: &Condition) -> String {
    match condition {
        Condition::PathPattern { pattern } => format!("path_pattern {pattern}"),
        Condition::CommandPattern { pattern } => format!("command_pattern {pattern}"),
        Condition::ServerAllowlist { servers } => {
            format!("server_allowlist {}", servers.join(", "))
        }
        Condition::ServerDenylist { servers } => format!("server_denylist {}", servers.join(", ")),
        Condition::ResourceType { types } => format!("resource_type {}", types.join(", ")),
    }
}

fn prompt_checklist(choices: &[ItemChoice], no_color: bool) -> Result<Option<Vec<bool>>> {
    let items = policy_setup::checklist();
    let labels: Vec<String> = items.iter().map(item_label).collect();
    let defaults: Vec<bool> = choices.iter().map(|choice| choice.enabled).collect();
    let picked = if no_color {
        MultiSelect::with_theme(&SimpleTheme)
            .with_prompt("Guard policy. Space toggles a rule. Enter confirms.")
            .items(&labels)
            .defaults(&defaults)
            .interact_opt()?
    } else {
        MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Guard policy. Space toggles a rule. Enter confirms.")
            .items(&labels)
            .defaults(&defaults)
            .interact_opt()?
    };
    let Some(indexes) = picked else {
        return Ok(None);
    };
    Ok(Some(
        (0..items.len())
            .map(|index| indexes.contains(&index))
            .collect(),
    ))
}

fn item_label(item: &ChecklistItem) -> String {
    format!("{}: {}", item.title, item.detail)
}

fn confirm(prompt: &str, default: bool, no_color: bool) -> Result<bool> {
    let answer = if no_color {
        Confirm::with_theme(&SimpleTheme)
            .with_prompt(prompt)
            .default(default)
            .interact()?
    } else {
        Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .default(default)
            .interact()?
    };
    Ok(answer)
}

fn offer_hooks(interactive: bool, no_color: bool) -> Result<()> {
    let installer = HookInstaller::new();
    let needed = agents_needing_hooks(&installer);
    if needed.is_empty() {
        return Ok(());
    }
    for agent in needed {
        let name = agent_label(agent);
        let id = agent_id(agent);
        if !interactive {
            println!("Run: balerx guard install {id}");
            continue;
        }
        if confirm(&format!("Install Guard hooks for {name}?"), false, no_color)? {
            let written = installer.install(agent)?;
            println!("Installed Guard hooks for {name}");
            for path in &written {
                println!("  {}", path.display());
            }
        }
    }
    Ok(())
}

fn agents_needing_hooks(installer: &HookInstaller) -> Vec<AgentType> {
    let status = installer.status();
    let mut needed = Vec::new();
    for agent in balerx_core::discovery::AgentDiscovery::new().discover_quiet() {
        match agent.definition_id.as_str() {
            "claude-code" if !status.claude_user && !status.claude_project => {
                needed.push(AgentType::ClaudeCode);
            }
            "cursor" if !status.cursor_user => needed.push(AgentType::Cursor),
            _ => {}
        }
    }
    needed
}

fn agent_label(agent: AgentType) -> &'static str {
    match agent {
        AgentType::ClaudeCode => "Claude Code",
        AgentType::Cursor => "Cursor",
    }
}

fn agent_id(agent: AgentType) -> &'static str {
    match agent {
        AgentType::ClaudeCode => "claude-code",
        AgentType::Cursor => "cursor",
    }
}

fn policy_path() -> Result<PathBuf> {
    if let Some(value) = std::env::var_os("BALERX_POLICY") {
        if !value.is_empty() {
            return Ok(PathBuf::from(value));
        }
    }
    let home =
        balerx_core::agent::absolute_home_dir().context(balerx_core::agent::HOME_REQUIRED)?;
    Ok(home.join(".balerx").join("policy.yaml"))
}

fn write_policy(path: &Path, policy: &Policy) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, to_yaml(policy)?).with_context(|| format!("Failed to write {}", path.display()))
}

fn backup_policy(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut dest = parent.join("policy.yaml.bak");
    let mut index = 1u32;
    while dest.exists() {
        dest = parent.join(format!("policy.yaml.bak.{index}"));
        index = index.saturating_add(1);
        if index > 1000 {
            anyhow::bail!("Too many policy.yaml.bak copies in {}", parent.display());
        }
    }
    fs::copy(path, &dest).with_context(|| format!("Failed to copy {}", path.display()))?;
    Ok(dest)
}
