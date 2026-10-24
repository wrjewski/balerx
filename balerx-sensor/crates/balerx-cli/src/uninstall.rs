//! `balerx uninstall` removes Guard hooks without using the network.

use anyhow::{Context, Result};
use balerx_core::agent::{home_dir, HOME_REQUIRED};
use balerx_core::guard::{strip_claude_file, strip_cursor_file, text_contains_balerx_hook};
use balerx_core::log::ActivityLog;
use clap::Args;
use dialoguer::theme::{ColorfulTheme, SimpleTheme};
use dialoguer::Confirm;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

/// PowerShell that deletes the Windows install folder. The running process cannot.
pub const WINDOWS_REMOVE_DIR: &str = r#"Remove-Item -Recurse -Force "$env:LOCALAPPDATA\balerx""#;

/// PowerShell that drops `%LOCALAPPDATA%\balerx` from the user Path and this window.
pub const WINDOWS_REMOVE_PATH: &str = r"$dest = Join-Path $env:LOCALAPPDATA 'balerx'
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$kept = @($userPath -split ';' | Where-Object { $_.Trim().TrimEnd('\') -ne $dest }) -join ';'
[Environment]::SetEnvironmentVariable('Path', $kept, 'User')
$env:Path = @($env:Path -split ';' | Where-Object { $_.Trim().TrimEnd('\') -ne $dest }) -join ';'";

const REFUSE_DATA: &str = "Refusing to purge. The data directory is not an absolute path.";
const REFUSE_ROOT: &str =
    "Refusing to purge. The data directory is the home directory or the filesystem root.";

#[derive(Debug, Clone, Args)]
pub struct UninstallArgs {
    /// Delete known policy files and activity logs. Unknown files stay.
    #[arg(long)]
    pub purge: bool,

    /// Remove the listed files without asking.
    #[arg(long)]
    pub yes: bool,
}

struct Plan {
    hooks: Vec<PathBuf>,
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
    kept: Vec<PathBuf>,
    config_dir: PathBuf,
    data_dir: PathBuf,
    config_exists: bool,
    data_exists: bool,
    refusal: Option<String>,
    unix_binary: Option<PathBuf>,
    other_unix_binary: Option<PathBuf>,
}

#[derive(Clone, Copy)]
struct PurgeOpts {
    windows: bool,
    data_dir_is_custom: bool,
}

struct Owned {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
    kept: Vec<PathBuf>,
}

pub fn run(args: &UninstallArgs, no_color: bool) -> Result<()> {
    let plan = plan(args.purge);
    print_plan(&plan, args.purge);
    if !args.yes && !std::io::stdin().is_terminal() {
        println!("No terminal attached. Nothing was removed.");
        println!("Run: balerx uninstall --yes");
        println!("Run: balerx uninstall --purge --yes");
        return Ok(());
    }
    if let Some(message) = &plan.refusal {
        anyhow::bail!(message.clone());
    }
    if plan.hooks.is_empty()
        && plan.unix_binary.is_none()
        && plan.files.is_empty()
        && plan.dirs.is_empty()
    {
        println!("Nothing to remove.");
        return Ok(());
    }
    if !args.yes && !confirm("Remove the files listed above?", false, no_color)? {
        println!("Uninstall cancelled. Nothing was removed.");
        return Ok(());
    }
    for path in &plan.hooks {
        strip_hook_file(path)?;
        println!("Removed Balerx hook commands from {}", path.display());
    }
    for path in &plan.files {
        remove_owned_file(path)?;
        println!("Removed {}", path.display());
    }
    for path in &plan.dirs {
        remove_empty_owned_dir(path)?;
        println!("Removed {}", path.display());
    }
    if let Some(path) = &plan.unix_binary {
        remove_owned_file(path)?;
        println!("Removed {}", path.display());
    }
    Ok(())
}

fn plan(purge: bool) -> Plan {
    let resolved_home = home_dir();
    let home_absolute = resolved_home
        .as_ref()
        .is_some_and(|path| path.is_absolute());
    let home = resolved_home.unwrap_or_default();
    let cwd = std::env::current_dir().unwrap_or_default();
    let data_dir = data_dir();
    let data_absolute = data_dir.is_absolute();
    let config_dir = home.join(".balerx");
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    let mut kept = Vec::new();
    let refusal = if purge {
        purge_refusal(&home, home_absolute, &data_dir, data_absolute)
    } else {
        None
    };
    if purge && refusal.is_none() {
        let owned = select_owned(
            &config_dir,
            &data_dir,
            PurgeOpts {
                windows: cfg!(windows),
                data_dir_is_custom: data_dir_is_custom(),
            },
        );
        files = owned.files;
        dirs = owned.dirs;
        kept = owned.kept;
    }
    let (unix_binary, other_unix_binary) = if home_absolute {
        unix_binary(&home)
    } else {
        (None, None)
    };
    Plan {
        hooks: hook_files(home_absolute.then_some(home.as_path()), &cwd),
        files,
        dirs,
        kept,
        config_exists: home_absolute && config_dir.is_dir(),
        data_exists: data_absolute && data_dir.is_dir(),
        config_dir,
        data_dir,
        refusal,
        unix_binary,
        other_unix_binary,
    }
}

fn purge_refusal(
    home: &Path,
    home_absolute: bool,
    data_dir: &Path,
    data_absolute: bool,
) -> Option<String> {
    let mut lines = Vec::new();
    if !home_absolute {
        lines.push(HOME_REQUIRED.to_string());
    }
    if !data_absolute {
        lines.push(REFUSE_DATA.to_string());
    }
    if home_absolute && data_absolute && (data_dir == home || data_dir.parent().is_none()) {
        lines.push(REFUSE_ROOT.to_string());
    }
    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

fn print_plan(plan: &Plan, purge: bool) {
    println!("Will remove:");
    if plan.hooks.is_empty()
        && plan.files.is_empty()
        && plan.dirs.is_empty()
        && plan.unix_binary.is_none()
    {
        println!("  No Balerx hook commands are installed.");
    }
    for path in &plan.hooks {
        println!("  Balerx hook commands in {}", path.display());
    }
    for path in &plan.files {
        println!("  {}", path.display());
    }
    for path in &plan.dirs {
        println!("  {}", path.display());
    }
    if let Some(path) = &plan.unix_binary {
        println!("  {}", path.display());
    }
    if purge {
        if !plan.kept.is_empty() {
            println!("Will keep:");
            for path in &plan.kept {
                println!("  {}", path.display());
                if path.is_symlink() {
                    println!("Left {} in place. It is a symlink.", path.display());
                }
            }
            println!("Unknown files stay.");
        }
    } else {
        println!("Will keep:");
        if plan.config_exists {
            println!("  {}", plan.config_dir.display());
        }
        if plan.data_exists {
            println!("  {}", plan.data_dir.display());
        }
        if !plan.config_exists && !plan.data_exists {
            println!("  No ~/.balerx directory and no activity log were found.");
        }
        println!("Policy and logs stay. Pass --purge to delete them.");
    }
    if let Some(path) = &plan.other_unix_binary {
        let current = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("this process"));
        println!(
            "Left {} in place. It is not the running binary ({}).",
            path.display(),
            current.display()
        );
    }
    if cfg!(windows) {
        println!("This command does not delete the running binary. Run this in PowerShell:");
        println!("  {WINDOWS_REMOVE_DIR}");
        for line in WINDOWS_REMOVE_PATH.lines() {
            println!("  {line}");
        }
    }
    if let Some(message) = &plan.refusal {
        println!("{message}");
    }
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

fn hook_files(home: Option<&Path>, cwd: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut candidates = Vec::new();
    if let Some(home) = home {
        candidates.push(home.join(".claude").join("settings.json"));
        candidates.push(home.join(".cursor").join("hooks.json"));
    }
    if cwd.is_absolute() {
        candidates.push(cwd.join(".claude").join("settings.json"));
    }
    for path in candidates {
        if path.is_absolute()
            && path.is_file()
            && contains_hook(&path)
            && !paths.iter().any(|existing| existing == &path)
        {
            paths.push(path);
        }
    }
    paths
}

fn contains_hook(path: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|text| text_contains_balerx_hook(&text))
}

fn strip_hook_file(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        anyhow::bail!("Refusing to edit relative path {}", path.display());
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if name.eq_ignore_ascii_case("hooks.json") {
        strip_cursor_file(path)
    } else {
        strip_claude_file(path)
    }
}

fn data_dir() -> PathBuf {
    let log_path = ActivityLog::default_log().path().to_path_buf();
    if let Some(parent) = log_path.parent().and_then(Path::parent) {
        return parent.to_path_buf();
    }
    log_path
}

fn data_dir_is_custom() -> bool {
    std::env::var_os("BALERX_DATA_DIR").is_some_and(|value| !value.is_empty())
}

fn unix_binary(home: &Path) -> (Option<PathBuf>, Option<PathBuf>) {
    if cfg!(windows) {
        return (None, None);
    }
    let installed = home.join(".local").join("bin").join("balerx");
    if !installed.is_file() {
        return (None, None);
    }
    if running_binary_is(&installed) {
        (Some(installed), None)
    } else {
        (None, Some(installed))
    }
}

fn running_binary_is(installed: &Path) -> bool {
    let Ok(current) = std::env::current_exe() else {
        return false;
    };
    if installed.is_symlink() {
        return false;
    }
    match (current.canonicalize(), installed.canonicalize()) {
        (Ok(current), Ok(installed)) => current == installed,
        _ => false,
    }
}

/// Files and directories Balerx may remove. `windows` is injected so the
/// install-folder rule can be tested on any host. A custom data directory is
/// never removed, even when it is empty.
fn select_owned(config_dir: &Path, data_dir: &Path, opts: PurgeOpts) -> Owned {
    let mut owned = Owned {
        files: Vec::new(),
        dirs: Vec::new(),
        kept: Vec::new(),
    };
    if config_dir.is_absolute() {
        classify_config(config_dir, &mut owned);
    }
    if data_dir.is_absolute() {
        classify_data(data_dir, opts, &mut owned);
    }
    owned.files.sort();
    owned
        .dirs
        .sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    owned.kept.sort();
    owned
}

fn classify_config(dir: &Path, owned: &mut Owned) {
    if !dir.is_absolute() || skip_untrusted_dir(dir, owned) {
        return;
    }
    let mut kept_inside = false;
    let mut canaries = None;
    for path in dir_children(dir) {
        let name = file_name(&path);
        if path.is_symlink() {
            owned.kept.push(path);
            kept_inside = true;
            continue;
        }
        if path.is_file() && is_known_policy_file(&name) {
            owned.files.push(path);
            continue;
        }
        if path.is_dir() && name == "canaries" {
            canaries = Some(path);
            continue;
        }
        owned.kept.push(path);
        kept_inside = true;
    }
    if let Some(canaries) = canaries {
        if classify_named_files(&canaries, &is_known_canary_file, owned) {
            kept_inside = true;
        } else {
            owned.dirs.push(canaries);
        }
    }
    if !kept_inside {
        owned.dirs.push(dir.to_path_buf());
    }
}

fn classify_data(dir: &Path, opts: PurgeOpts, owned: &mut Owned) {
    if !dir.is_absolute() || skip_untrusted_dir(dir, owned) {
        return;
    }
    let mut kept_inside = false;
    let mut logs = None;
    for path in dir_children(dir) {
        let name = file_name(&path);
        if path.is_symlink() {
            owned.kept.push(path);
            kept_inside = true;
            continue;
        }
        if path.is_file() && name == "canaries.json" {
            owned.files.push(path);
            continue;
        }
        if path.is_dir() && name == "logs" {
            logs = Some(path);
            continue;
        }
        owned.kept.push(path);
        kept_inside = true;
    }
    if let Some(logs) = logs {
        if classify_named_files(&logs, &is_activity_log, owned) {
            kept_inside = true;
        } else {
            owned.dirs.push(logs);
        }
    }
    let name = file_name(dir);
    let owned_name = name == "balerx" || name == ".balerx";
    if !kept_inside && owned_name && !opts.windows && !opts.data_dir_is_custom {
        owned.dirs.push(dir.to_path_buf());
    }
}

/// Returns true when something inside `dir` was kept.
fn classify_named_files(dir: &Path, known: &dyn Fn(&str) -> bool, owned: &mut Owned) -> bool {
    if skip_untrusted_dir(dir, owned) {
        return true;
    }
    let mut kept_inside = false;
    for path in dir_children(dir) {
        let name = file_name(&path);
        if path.is_symlink() || !path.is_file() || !known(&name) {
            owned.kept.push(path);
            kept_inside = true;
            continue;
        }
        owned.files.push(path);
    }
    kept_inside
}

fn skip_untrusted_dir(dir: &Path, owned: &mut Owned) -> bool {
    if dir.is_symlink() || !dir.is_dir() {
        if dir.symlink_metadata().is_ok() {
            owned.kept.push(dir.to_path_buf());
        }
        return true;
    }
    false
}

fn dir_children(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .collect()
        })
        .unwrap_or_default()
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_string()
}

fn is_known_policy_file(name: &str) -> bool {
    name == "policy.yaml" || name == "policy.yaml.bak" || is_numbered_policy_backup(name)
}

fn is_numbered_policy_backup(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("policy.yaml.bak.") else {
        return false;
    };
    !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_digit())
}

fn is_known_canary_file(name: &str) -> bool {
    matches!(name, "credentials" | ".env" | "id_rsa" | "secret.txt")
}

fn is_activity_log(name: &str) -> bool {
    name == "activity.jsonl"
}

fn remove_owned_file(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.is_symlink() || !path.is_file() {
        anyhow::bail!("Refusing to delete {}", path.display());
    }
    fs::remove_file(path).with_context(|| format!("Failed to remove {}", path.display()))
}

fn remove_empty_owned_dir(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.is_symlink() || path.parent().is_none() {
        anyhow::bail!("Refusing to delete {}", path.display());
    }
    let name = file_name(path);
    if !matches!(name.as_str(), ".balerx" | "balerx" | "logs" | "canaries") {
        anyhow::bail!("Refusing to delete {}", path.display());
    }
    if fs::read_dir(path)?.next().is_some() {
        anyhow::bail!("Refusing to delete non-empty directory {}", path.display());
    }
    fs::remove_dir(path).with_context(|| format!("Failed to remove {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "balerx-uninstall-unit-{label}-{}-{id}-{nanos}",
            std::process::id(),
        ));
        fs::create_dir(&dir).unwrap_or_else(|err| panic!("temp dir {}: {err}", dir.display()));
        dir
    }

    #[test]
    fn custom_data_dir_keeps_unrelated_files_and_the_directory() {
        let home = temp_dir("home");
        let data = temp_dir("documents");
        fs::create_dir_all(home.join(".balerx")).expect("config");
        fs::write(home.join(".balerx").join("policy.yaml"), "version: 1\n").expect("policy");
        fs::write(home.join(".balerx").join("policy.yaml.bak"), "old\n").expect("bak");
        fs::write(home.join(".balerx").join("notes.txt"), "keep\n").expect("notes");
        fs::create_dir_all(data.join("logs")).expect("logs");
        fs::write(data.join("logs").join("activity.jsonl"), "{}\n").expect("log");
        fs::write(data.join("canaries.json"), "{}\n").expect("registry");
        fs::create_dir_all(data.join("photos")).expect("photos");
        fs::write(data.join("photos").join("pic.txt"), "pic\n").expect("pic");

        let owned = select_owned(
            &home.join(".balerx"),
            &data,
            PurgeOpts {
                windows: false,
                data_dir_is_custom: true,
            },
        );
        assert!(owned.files.iter().any(|path| path.ends_with("policy.yaml")));
        assert!(owned
            .files
            .iter()
            .any(|path| path.ends_with("policy.yaml.bak")));
        assert!(owned
            .files
            .iter()
            .any(|path| path.ends_with("activity.jsonl")));
        assert!(owned
            .files
            .iter()
            .any(|path| path.ends_with("canaries.json")));
        assert!(owned.dirs.iter().any(|path| path.ends_with("logs")));
        assert!(!owned.dirs.iter().any(|path| path == &data));
        assert!(!owned.dirs.iter().any(|path| path.ends_with(".balerx")));
        assert!(owned.kept.iter().any(|path| path.ends_with("notes.txt")));
        assert!(owned.kept.iter().any(|path| path.ends_with("photos")));
        let _ = fs::remove_dir_all(home);
        let _ = fs::remove_dir_all(data);
    }

    #[test]
    fn windows_purge_leaves_the_program_binary() {
        let root = temp_dir("win-data");
        fs::write(root.join("balerx.exe"), "binary").expect("exe");
        fs::create_dir_all(root.join("logs")).expect("logs");
        fs::write(root.join("logs").join("activity.jsonl"), "{}\n").expect("log");
        fs::write(root.join("canaries.json"), "{}\n").expect("registry");

        let config = temp_dir("win-config").join(".balerx");
        fs::create_dir_all(&config).expect("config");
        fs::write(config.join("policy.yaml"), "version: 1\n").expect("policy");

        let owned = select_owned(
            &config,
            &root,
            PurgeOpts {
                windows: true,
                data_dir_is_custom: false,
            },
        );
        assert!(owned
            .files
            .iter()
            .any(|path| path.ends_with("activity.jsonl")));
        assert!(owned.files.iter().any(|path| path.ends_with("policy.yaml")));
        assert!(owned.dirs.iter().any(|path| path.ends_with("logs")));
        assert!(owned.dirs.iter().any(|path| path.ends_with(".balerx")));
        assert!(!owned.files.iter().any(|path| path.ends_with("balerx.exe")));
        assert!(!owned.dirs.iter().any(|path| path == &root));
        assert!(owned.kept.iter().any(|path| path.ends_with("balerx.exe")));
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(config.parent().expect("parent"));
    }

    #[test]
    fn relative_paths_are_not_purge_targets() {
        let owned = select_owned(
            Path::new(".balerx"),
            Path::new("balerx"),
            PurgeOpts {
                windows: false,
                data_dir_is_custom: true,
            },
        );
        assert_eq!(owned.files, Vec::<PathBuf>::new());
        assert_eq!(owned.dirs, Vec::<PathBuf>::new());
    }

    #[test]
    fn missing_home_is_a_purge_refusal() {
        let message =
            purge_refusal(Path::new("."), false, Path::new("balerx"), false).expect("refusal");
        assert!(message.contains(HOME_REQUIRED));
        assert!(message.contains(REFUSE_DATA));
        assert!(
            purge_refusal(Path::new("/home/ada"), true, Path::new("/"), true)
                .expect("root")
                .contains(REFUSE_ROOT)
        );
        assert!(
            purge_refusal(Path::new("/home/ada"), true, Path::new("/home/ada"), true)
                .expect("home")
                .contains(REFUSE_ROOT)
        );
        assert!(purge_refusal(
            Path::new("/home/ada"),
            true,
            Path::new("/home/ada/Documents"),
            true
        )
        .is_none());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_logs_are_not_entered() {
        let data = temp_dir("link-data");
        let outside = temp_dir("outside");
        fs::write(outside.join("secret.txt"), "secret\n").expect("secret");
        std::os::unix::fs::symlink(outside.join("secret.txt"), data.join("logs")).expect("link");
        fs::write(data.join("canaries.json"), "{}\n").expect("registry");
        let config = temp_dir("link-config");
        let owned = select_owned(
            &config.join(".balerx"),
            &data,
            PurgeOpts {
                windows: false,
                data_dir_is_custom: true,
            },
        );
        assert!(owned.kept.iter().any(|path| path.ends_with("logs")));
        assert!(!owned.dirs.iter().any(|path| path.ends_with("logs")));
        assert!(outside.join("secret.txt").is_file());
        let _ = fs::remove_dir_all(data);
        let _ = fs::remove_dir_all(outside);
        let _ = fs::remove_dir_all(config);
    }
}
