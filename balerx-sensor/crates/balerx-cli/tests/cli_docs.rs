use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn docs_dir() -> PathBuf {
    repo_root().join("apps/balerx-web/content/docs")
}

fn run_help(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_balerx"))
        .args(args)
        .env("COLUMNS", "100")
        .output()
        .expect("run balerx help");
    assert!(
        output.status.success(),
        "balerx {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n")
}

fn help_commands() -> Vec<Vec<&'static str>> {
    vec![
        vec!["--help"],
        vec!["scan", "--help"],
        vec!["lock", "--help"],
        vec!["diff", "--help"],
        vec!["guard", "--help"],
        vec!["guard", "install", "--help"],
        vec!["guard", "uninstall", "--help"],
        vec!["guard", "status", "--help"],
        vec!["hook", "--help"],
        vec!["log", "--help"],
        vec!["log", "view", "--help"],
        vec!["canary", "--help"],
        vec!["canary", "plant", "--help"],
        vec!["canary", "remove", "--help"],
        vec!["canary", "list", "--help"],
        vec!["canary", "check", "--help"],
        vec!["upload", "--help"],
        vec!["policy", "--help"],
        vec!["policy", "pull", "--help"],
        vec!["doctor", "--help"],
        vec!["completions", "--help"],
        vec!["self-update", "--help"],
    ]
}

fn render_help() -> String {
    let mut blocks = Vec::new();
    for args in help_commands() {
        let heading = if args == ["--help"] {
            "balerx --help".to_string()
        } else {
            format!("balerx {}", args.join(" "))
        };
        blocks.push(format!("{heading}\n\n{}", run_help(&args).trim_end()));
    }
    format!("\n```\n{}\n```\n", blocks.join("\n\n"))
}

fn walk_markdown(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|_| panic!("read {}", dir.display())) {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            walk_markdown(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "md") {
            files.push(path);
        }
    }
}

fn is_boundary(ch: Option<char>) -> bool {
    match ch {
        None => true,
        Some(value) => !value.is_ascii_alphanumeric() && value != '_' && value != '-',
    }
}

fn is_invocation(line: &str) -> bool {
    let mut rest = line;
    while let Some(index) = rest.find("balerx") {
        let before = rest[..index].chars().next_back();
        let after = rest[index + "balerx".len()..].chars().next();
        if is_boundary(before) && matches!(after, Some(ch) if ch.is_whitespace()) {
            return true;
        }
        rest = &rest[index + "balerx".len()..];
    }
    false
}

fn long_flags(line: &str) -> Vec<String> {
    let mut flags = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut index = 0;
    while index + 1 < chars.len() {
        if chars[index] == '-' && chars[index + 1] == '-' {
            let start = index;
            index += 2;
            let name_start = index;
            while index < chars.len()
                && (chars[index].is_ascii_alphanumeric() || chars[index] == '-')
            {
                index += 1;
            }
            if index > name_start {
                flags.push(chars[start..index].iter().collect());
            }
            continue;
        }
        index += 1;
    }
    flags
}

fn subcommand_token(line: &str) -> Option<String> {
    let mut search = 0;
    while let Some(rel) = line[search..].find("balerx") {
        let index = search + rel;
        let before = if index == 0 {
            None
        } else {
            line[..index].chars().next_back()
        };
        let after_index = index + "balerx".len();
        let after = line[after_index..].chars().next();
        if is_boundary(before) && matches!(after, Some(ch) if ch.is_whitespace()) {
            let token = line[after_index..]
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches(|ch: char| ch == '"' || ch == '\'' || ch == '`');
            if token.len() > 1
                && token.starts_with(|ch: char| ch.is_ascii_lowercase())
                && token
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
            {
                return Some(token.to_string());
            }
        }
        search = after_index;
    }
    None
}

#[test]
fn documented_cli_flags_exist() {
    let cli_path = docs_dir().join("cli.md");
    // The public scanner repository does not include the web app docs.
    if !cli_path.is_file() {
        return;
    }

    let mut known_flags = std::collections::BTreeSet::new();
    let mut known_commands = std::collections::BTreeSet::new();
    let rendered = render_help();
    for flag in long_flags(&rendered) {
        known_flags.insert(flag);
    }
    for args in help_commands() {
        if let Some(command) = args.iter().find(|arg| !arg.starts_with('-')) {
            known_commands.insert((*command).to_string());
        }
    }
    known_commands.insert("help".to_string());

    let original = fs::read_to_string(&cli_path).expect("read cli.md");
    let start = original
        .find("<!-- cli-help:start -->")
        .expect("cli help start marker");
    let end = original
        .find("<!-- cli-help:end -->")
        .expect("cli help end marker");
    let updated = format!(
        "{}<!-- cli-help:start -->{}<!-- cli-help:end -->{}",
        &original[..start],
        rendered,
        &original[end + "<!-- cli-help:end -->".len()..]
    );
    if std::env::var("BALERX_UPDATE_CLI_DOCS").ok().as_deref() == Some("1") {
        fs::write(&cli_path, &updated).expect("write cli.md");
    }

    let mut files = Vec::new();
    walk_markdown(&docs_dir(), &mut files);
    files.sort();
    let mut missing_flags = Vec::new();
    let mut missing_commands = Vec::new();
    for path in files {
        let text = fs::read_to_string(&path)
            .expect("read doc")
            .replace("\r\n", "\n");
        let mut in_fence = false;
        for line in text.lines() {
            if line.starts_with("```") {
                in_fence = !in_fence;
                continue;
            }
            if !in_fence || !is_invocation(line) {
                continue;
            }
            for flag in long_flags(line) {
                if !known_flags.contains(&flag) {
                    missing_flags.push(format!("{}: {flag}", path.display()));
                }
            }
            if let Some(command) = subcommand_token(line) {
                if !known_commands.contains(&command) {
                    missing_commands.push(format!("{}: {command}", path.display()));
                }
            }
        }
    }
    assert!(
        missing_flags.is_empty(),
        "documented flags missing from clap help:\n{}",
        missing_flags.join("\n")
    );
    assert!(
        missing_commands.is_empty(),
        "documented commands missing from clap help:\n{}",
        missing_commands.join("\n")
    );
}
