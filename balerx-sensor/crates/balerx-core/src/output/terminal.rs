use crate::finding::{Finding, FindingSeverity, ScanResult};

pub fn print_scan_result(result: &ScanResult) {
    println!("\n╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║             Balerx Gate Security Scan Results                        ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝\n");

    println!("Device: {}", result.device.hostname);
    println!(
        "Platform: {} {}",
        result.device.platform, result.device.os_version
    );
    println!(
        "Scanned: {}\n",
        result.scanned_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    let risk_indicator = match result.summary.risk_score {
        0..=25 => "✓ LOW",
        26..=50 => "⚠ MEDIUM",
        51..=75 => "⚠ HIGH",
        _ => "✗ CRITICAL",
    };

    println!("╭─────────────────────────────────────────────────────────────────────╮");
    println!(
        "│ RISK SCORE: {}/100 [{}]",
        result.summary.risk_score, risk_indicator
    );
    println!("├─────────────────────────────────────────────────────────────────────┤");
    println!(
        "│ Agents Found:    {:<5}                                           │",
        result.summary.agents_found
    );
    println!(
        "│ Total Findings:  {:<5}                                           │",
        result.summary.findings_count
    );
    println!(
        "│ Critical:        {:<5}                                           │",
        result.summary.critical_count
    );
    println!(
        "│ High:            {:<5}                                           │",
        result.summary.high_count
    );
    println!(
        "│ Medium:          {:<5}                                           │",
        result.summary.medium_count
    );
    println!(
        "│ Low:             {:<5}                                           │",
        result.summary.low_count
    );
    println!("╰─────────────────────────────────────────────────────────────────────╯\n");

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
    let reset = "\x1b[0m";

    println!(
        "┌─ {}[{}]{} {} ({})",
        severity_color, severity_label, reset, finding.title, finding.rule_id
    );
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

    println!("└───────────────────────────────────────────────────────────────────────\n");
}
