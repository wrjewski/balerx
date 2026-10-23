use crate::finding::{Finding, FindingSeverity, ScanResult};

fn color_enabled() -> bool {
    if no_color() {
        return false;
    }
    std::io::IsTerminal::is_terminal(&std::io::stdout())
}

/// True when color should be off. `--no-color` is the same switch as `NO_COLOR`.
#[must_use]
pub fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some() || std::env::args().any(|arg| arg == "--no-color")
}

const INNER: usize = 69;

fn bar(left: char, fill: char, right: char) -> String {
    format!("{left}{}{right}", fill.to_string().repeat(INNER))
}

fn paint(text: &str, code: &str) -> String {
    if color_enabled() {
        format!("{code}{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn row(text: &str) -> String {
    let width = INNER.saturating_sub(2);
    format!("│ {text:<width$} │")
}

pub fn print_scan_result(result: &ScanResult) {
    let title = "Balerx Gate Security Scan Results";
    let pad = INNER.saturating_sub(title.len());
    let left = pad / 2;
    let right = pad - left;
    let mut heading = String::from("║");
    heading.push_str(&" ".repeat(left));
    heading.push_str(title);
    heading.push_str(&" ".repeat(right));
    heading.push('║');
    println!("\n{}", bar('╔', '═', '╗'));
    println!("{heading}");
    println!("{}\n", bar('╚', '═', '╝'));

    println!("Device: {}", result.device.hostname);
    println!(
        "Platform: {} {}",
        result.device.platform, result.device.os_version
    );
    let local = result.scanned_at.with_timezone(&chrono::Local);
    println!("Scanned: {}\n", local.format("%Y-%m-%d %H:%M:%S %:z"));

    let risk_indicator = result.summary.risk_label();

    println!("{}", bar('╭', '─', '╮'));
    println!(
        "{}",
        row(&format!(
            "RISK SCORE: {}/100 [{risk_indicator}]",
            result.summary.risk_score
        ))
    );
    println!("{}", bar('├', '─', '┤'));
    println!(
        "{}",
        row(&format!("Agents Found:    {}", result.summary.agents_found))
    );
    println!(
        "{}",
        row(&format!(
            "Total Findings:  {}",
            result.summary.findings_count
        ))
    );
    println!(
        "{}",
        row(&format!(
            "Critical:        {}",
            result.summary.critical_count
        ))
    );
    println!(
        "{}",
        row(&format!("High:            {}", result.summary.high_count))
    );
    println!(
        "{}",
        row(&format!("Medium:          {}", result.summary.medium_count))
    );
    println!(
        "{}",
        row(&format!("Low:             {}", result.summary.low_count))
    );
    println!("{}\n", bar('╰', '─', '╯'));

    if !result.agents.is_empty() {
        println!("DISCOVERED AGENTS:");
        for agent in &result.agents {
            let status_indicator = match agent.status {
                crate::agent::AgentStatus::Configured => "✓",
                crate::agent::AgentStatus::Running => "▶",
                _ => "·",
            };
            println!(
                "  {} {} ({})",
                status_indicator, agent.name, agent.definition_id
            );
            if !agent.config_paths.is_empty() {
                for path in &agent.config_paths {
                    println!("      Config: {}", path.display());
                }
            }
        }
        println!();
    }

    if result.findings.is_empty() {
        println!("✓ No security findings detected.\n");
    } else {
        println!("FINDINGS:\n");

        for finding in &result.findings {
            print_finding(finding);
        }
    }
}

fn print_finding(finding: &Finding) {
    let (severity_label, severity_color) = match finding.severity {
        FindingSeverity::Critical => ("CRITICAL", "\x1b[91m"),
        FindingSeverity::High => ("HIGH    ", "\x1b[31m"),
        FindingSeverity::Medium => ("MEDIUM  ", "\x1b[33m"),
        FindingSeverity::Low => ("LOW     ", "\x1b[36m"),
        FindingSeverity::Info => ("INFO    ", "\x1b[34m"),
    };
    let label = paint(&format!("[{severity_label}]"), severity_color);

    println!("┌─ {label} {} ({})", finding.title, finding.rule_id);
    println!("│");
    println!("│  {}", finding.description);

    if let Some(agent) = &finding.affected_agent {
        println!("│  Agent: {agent}");
    }

    println!("│  Resource: {}", finding.affected_resource);

    if let Some(fix) = &finding.suggested_fix {
        println!("│");
        println!("│  💡 Suggested Fix:");
        println!("│     {fix}");
    }

    println!("{}\n", bar('└', '─', '┘'));
}

#[cfg(test)]
mod tests {
    use super::{bar, row};

    #[test]
    fn report_borders_share_one_width() {
        let top = bar('╔', '═', '╗');
        let risk = bar('╭', '─', '╮');
        let foot = bar('└', '─', '┘');
        let line = row("RISK SCORE: 14/100 [LOW]");
        assert_eq!(top.chars().count(), risk.chars().count());
        assert_eq!(risk.chars().count(), foot.chars().count());
        assert_eq!(foot.chars().count(), line.chars().count());
    }
}
