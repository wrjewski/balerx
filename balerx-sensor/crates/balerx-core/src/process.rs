use serde::{Deserialize, Serialize};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub cmd: Vec<String>,
    pub parent_pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub pid: Option<u32>,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
}

pub struct ProcessCollector {
    system: System,
}

/// Exact match of a process basename. `cursor-agent-st` does not match `cursor`.
/// A trailing `.exe` is ignored, and the comparison is case-insensitive.
#[must_use]
pub fn process_name_matches(process_name: &str, expected: &str) -> bool {
    let base = process_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(process_name);
    let stem = strip_exe_suffix(base);
    stem.eq_ignore_ascii_case(expected)
}

fn strip_exe_suffix(name: &str) -> &str {
    let Some(split) = name.len().checked_sub(4) else {
        return name;
    };
    if name[split..].eq_ignore_ascii_case(".exe") {
        &name[..split]
    } else {
        name
    }
}

impl ProcessCollector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            system: System::new_all(),
        }
    }

    pub fn refresh(&mut self) {
        self.system.refresh_all();
    }

    pub fn find_agent_processes(&mut self, agent_names: &[String]) -> Vec<ProcessSnapshot> {
        self.refresh();

        let mut matches = Vec::new();

        for (pid, process) in self.system.processes() {
            let process_name = process.name().to_string_lossy();

            for agent_name in agent_names {
                if process_name_matches(&process_name, agent_name) {
                    let cmd: Vec<String> = process
                        .cmd()
                        .iter()
                        .map(|s| s.to_string_lossy().to_string())
                        .collect();

                    matches.push(ProcessSnapshot {
                        pid: pid.as_u32(),
                        name: process_name.to_string(),
                        exe_path: process
                            .exe()
                            .and_then(|p| p.to_str())
                            .map(std::string::ToString::to_string),
                        cmd,
                        parent_pid: process.parent().map(sysinfo::Pid::as_u32),
                    });
                    break;
                }
            }
        }

        matches
    }

    #[must_use]
    pub fn get_network_connections(&self) -> Vec<NetworkConnection> {
        let mut connections = Vec::new();

        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = std::process::Command::new("netstat")
                .args(["-ano"])
                .output()
            {
                if let Ok(stdout) = String::from_utf8(output.stdout) {
                    for line in stdout.lines().skip(4) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 5 && parts[0] == "TCP" {
                            let local = parts[1].to_string();
                            let remote = parts[2].to_string();
                            let state = parts[3].to_string();
                            let pid = parts[4].parse::<u32>().ok();

                            connections.push(NetworkConnection {
                                pid,
                                local_addr: local,
                                remote_addr: remote,
                                state,
                            });
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = std::process::Command::new("netstat")
                .args(["-anv", "-p", "tcp"])
                .output()
            {
                if let Ok(stdout) = String::from_utf8(output.stdout) {
                    for line in stdout.lines().skip(2) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 9 && (parts[0] == "tcp4" || parts[0] == "tcp6") {
                            let local = format!("{}.{}", parts[3], parts[5]);
                            let remote = format!("{}.{}", parts[4], parts[6]);
                            let state = parts[7].to_string();
                            let pid = parts[8].parse::<u32>().ok();

                            connections.push(NetworkConnection {
                                pid,
                                local_addr: local,
                                remote_addr: remote,
                                state,
                            });
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = std::process::Command::new("ss").args(["-tnp"]).output() {
                if let Ok(stdout) = String::from_utf8(output.stdout) {
                    for line in stdout.lines().skip(1) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 6 {
                            let state = parts[0].to_string();
                            let local = parts[3].to_string();
                            let remote = parts[4].to_string();

                            let pid = if parts.len() >= 6 {
                                parts[5]
                                    .split(',')
                                    .find(|s| s.starts_with("pid="))
                                    .and_then(|s| s.strip_prefix("pid="))
                                    .and_then(|s| s.parse::<u32>().ok())
                            } else {
                                None
                            };

                            connections.push(NetworkConnection {
                                pid,
                                local_addr: local,
                                remote_addr: remote,
                                state,
                            });
                        }
                    }
                }
            }
        }

        connections
    }
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::process_name_matches;

    #[test]
    fn process_match_is_the_basename_only() {
        assert!(process_name_matches("cursor", "cursor"));
        assert!(process_name_matches("Cursor.exe", "cursor"));
        assert!(process_name_matches(
            r"C:\Program Files\Cursor\Cursor.exe",
            "Cursor"
        ));
        assert!(!process_name_matches("cursor-agent-st", "cursor"));
        assert!(!process_name_matches("cursor-helper", "cursor"));
    }
}
