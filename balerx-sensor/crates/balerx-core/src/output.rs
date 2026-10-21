use crate::finding::{FindingSeverity, ScanResult};
use anyhow::Result;
use std::fs;
use std::path::Path;

pub mod sarif;
pub mod terminal;

/// Write scan results to a JSON file
///
/// # Errors
/// Returns an error if the file cannot be written
pub fn write_json(result: &ScanResult, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    fs::write(path, json)?;
    Ok(())
}

/// Write scan results to a SARIF file
///
/// # Errors
/// Returns an error if the file cannot be written
pub fn write_sarif(result: &ScanResult, path: &Path) -> Result<()> {
    let sarif = sarif::to_sarif(result);
    let json = serde_json::to_string_pretty(&sarif)?;
    fs::write(path, json)?;
    Ok(())
}

/// Write scan results to an HTML report file
///
/// # Errors
/// Returns an error if the file cannot be written
pub fn write_html(result: &ScanResult, path: &Path) -> Result<()> {
    let html = generate_html_report(result);
    fs::write(path, html)?;
    Ok(())
}

// HTML template generation: length is acceptable for markup-heavy code
#[allow(clippy::too_many_lines, clippy::format_collect)]
fn generate_html_report(result: &ScanResult) -> String {
    let risk_color = match result.summary.risk_score {
        0..=25 => "#22c55e",
        26..=50 => "#eab308",
        51..=75 => "#f97316",
        _ => "#ef4444",
    };

    let findings_html: String = result
        .findings
        .iter()
        .map(|f| {
            let severity_badge = match f.severity {
                FindingSeverity::Critical => r#"<span class="badge critical">CRITICAL</span>"#,
                FindingSeverity::High => r#"<span class="badge high">HIGH</span>"#,
                FindingSeverity::Medium => r#"<span class="badge medium">MEDIUM</span>"#,
                FindingSeverity::Low => r#"<span class="badge low">LOW</span>"#,
                FindingSeverity::Info => r#"<span class="badge info">INFO</span>"#,
            };

            let fix_html = f
                .suggested_fix
                .as_ref()
                .map(|fix| {
                    format!(
                        r#"<div class="fix"><strong>Suggested Fix:</strong> {}</div>"#,
                        html_escape(fix)
                    )
                })
                .unwrap_or_default();

            format!(
                r#"<div class="finding">
                    <div class="finding-header">
                        {}<h3>{}</h3>
                    </div>
                    <p>{}</p>
                    <div class="detail"><strong>Resource:</strong> {}</div>
                    {}
                </div>"#,
                severity_badge,
                html_escape(&f.title),
                html_escape(&f.description),
                html_escape(&f.affected_resource),
                fix_html
            )
        })
        .collect();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Balerx Gate Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background: #f9fafb;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
        }}
        h1 {{
            font-size: 2rem;
            margin-bottom: 0.5rem;
            color: #111827;
        }}
        .meta {{
            color: #6b7280;
            font-size: 0.875rem;
        }}
        .summary {{
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
        }}
        .risk-score {{
            text-align: center;
            padding: 1.5rem;
            border-radius: 8px;
            background: #f3f4f6;
            margin-bottom: 1.5rem;
        }}
        .risk-number {{
            font-size: 3rem;
            font-weight: bold;
            color: {};
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
        }}
        .stat {{
            text-align: center;
            padding: 1rem;
            background: #f9fafb;
            border-radius: 8px;
        }}
        .stat-value {{
            font-size: 1.5rem;
            font-weight: bold;
            color: #111827;
        }}
        .stat-label {{
            font-size: 0.875rem;
            color: #6b7280;
            text-transform: uppercase;
        }}
        .findings {{
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .finding {{
            padding: 1.5rem;
            margin-bottom: 1rem;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            background: #fafafa;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 0.75rem;
        }}
        .finding h3 {{
            font-size: 1.125rem;
            color: #111827;
        }}
        .badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge.critical {{ background: #fef2f2; color: #991b1b; }}
        .badge.high {{ background: #fff7ed; color: #9a3412; }}
        .badge.medium {{ background: #fefce8; color: #854d0e; }}
        .badge.low {{ background: #f0fdf4; color: #166534; }}
        .badge.info {{ background: #eff6ff; color: #1e40af; }}
        .detail {{
            margin-top: 0.75rem;
            font-size: 0.875rem;
            color: #6b7280;
        }}
        .fix {{
            margin-top: 1rem;
            padding: 1rem;
            background: #f0fdf4;
            border-left: 4px solid #22c55e;
            border-radius: 4px;
            font-size: 0.875rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Balerx Gate Security Scan</h1>
            <div class="meta">
                Scanned: {} | Device: {} | Platform: {}
            </div>
        </header>

        <div class="summary">
            <div class="risk-score">
                <div class="risk-number">{}</div>
                <div class="stat-label">Risk Score</div>
            </div>
            <div class="stats">
                <div class="stat">
                    <div class="stat-value">{}</div>
                    <div class="stat-label">Agents Found</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{}</div>
                    <div class="stat-label">Medium</div>
                </div>
            </div>
        </div>

        <div class="findings">
            <h2 style="margin-bottom: 1.5rem;">Findings</h2>
            {}
        </div>
    </div>
</body>
</html>"#,
        risk_color,
        result.scanned_at.format("%Y-%m-%d %H:%M:%S UTC"),
        html_escape(&result.device.hostname),
        html_escape(&result.device.platform),
        result.summary.risk_score,
        result.summary.agents_found,
        result.summary.findings_count,
        result.summary.critical_count,
        result.summary.high_count,
        result.summary.medium_count,
        findings_html
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
