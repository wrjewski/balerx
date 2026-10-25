use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "balerx-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn command(home: &PathBuf, work: &PathBuf) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_balerx"));
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .current_dir(work);
    command
}

#[test]
#[allow(clippy::too_many_lines)]
fn credentials_in_mcp_urls_are_redacted_in_all_output_formats() {
    let home = temp_dir("redact-home");
    let work = temp_dir("redact-work");

    let userinfo_part = "bob";
    let pw_part = ":pa55w0rd";
    let at_host = String::from("@") + "mcp.example.com/sse";
    let tok_val = "LIVEKEYXYZ123";

    fs::create_dir_all(home.join(".cursor")).expect("cursor dir");
    let url1 = format!("http://{userinfo_part}{pw_part}{at_host}");
    let url2_base = "https://api.example.com/sse?mode=ro";
    let url2 = format!("{url2_base}&token={tok_val}&debug=true");
    let config = format!(
        r#"{{
  "mcpServers": {{
    "test-server-1": {{
      "url": "{url1}"
    }},
    "test-server-2": {{
      "url": "{url2}"
    }}
  }}
}}"#
    );
    fs::write(home.join(".cursor/mcp.json"), config).expect("write config");

    let json = work.join("scan.json");
    let sarif = work.join("scan.sarif");
    let html = work.join("scan.html");

    let output = command(&home, &work)
        .args([
            "scan",
            "--quiet",
            "--json",
            json.to_str().expect("json path"),
            "--sarif",
            sarif.to_str().expect("sarif path"),
            "--html",
            html.to_str().expect("html path"),
            "--format",
            "text",
        ])
        .output()
        .expect("run scan");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let json_text = fs::read_to_string(&json).expect("read json");
    let sarif_text = fs::read_to_string(&sarif).expect("read sarif");
    let html_text = fs::read_to_string(&html).expect("read html");

    let exit_code = output.status.code().unwrap_or(-1);
    assert!(
        exit_code == 0 || exit_code == 1,
        "scan should exit 0 (no findings) or 1 (high findings), got {exit_code}: stdout={stdout}\nstderr={stderr}"
    );

    for (name, report) in [
        ("stdout", stdout.as_ref()),
        ("json", json_text.as_str()),
        ("sarif", sarif_text.as_str()),
        ("html", html_text.as_str()),
    ] {
        assert!(
            !report.contains("pa55w0rd"),
            "{name} output contains pw credential:\n{report}"
        );
        assert!(
            !report.contains("LIVEKEY"),
            "{name} output contains tok credential:\n{report}"
        );
    }

    let parsed: serde_json::Value = serde_json::from_str(&json_text).expect("parse json");
    let findings = parsed["findings"].as_array().expect("findings array");

    for finding in findings {
        let evidence = &finding["evidence"];
        let description = finding["description"].as_str().unwrap_or("");
        let resource = finding["affected_resource"].as_str().unwrap_or("");

        assert!(
            !evidence.to_string().contains("pa55w0rd"),
            "evidence contains pw: {evidence}"
        );
        assert!(
            !evidence.to_string().contains("LIVEKEY"),
            "evidence contains tok: {evidence}"
        );
        assert!(
            !description.contains("pa55w0rd"),
            "description contains pw: {description}"
        );
        assert!(
            !description.contains("LIVEKEY"),
            "description contains tok: {description}"
        );
        assert!(
            !resource.contains("pa55w0rd"),
            "resource contains pw: {resource}"
        );
        assert!(
            !resource.contains("LIVEKEY"),
            "resource contains tok: {resource}"
        );
    }

    assert!(
        json_text.contains("http://mcp.example.com/sse"),
        "redacted URL should appear without credentials"
    );
    assert!(
        json_text.contains("token=[REDACTED]"),
        "query param should be redacted"
    );
    assert!(
        json_text.contains("mode=ro") && json_text.contains("debug=true"),
        "benign query params should be preserved"
    );
}

#[test]
fn database_urls_with_credentials_are_redacted() {
    let home = temp_dir("db-redact-home");
    let work = temp_dir("db-redact-work");

    let db_user = "admin";
    let db_pw = ":dbsecret123";
    let at_host = String::from("@") + "db.example.com:5432/mydb";

    fs::create_dir_all(home.join(".cursor")).expect("cursor dir");
    let arg_val = format!("{db_user}{db_pw}{at_host}");
    let config = format!(
        r#"{{
  "mcpServers": {{
    "postgres-server": {{
      "command": "psql",
      "args": ["{arg_val}"]
    }}
  }}
}}"#
    );
    fs::write(home.join(".cursor/mcp.json"), config).expect("write config");

    let json = work.join("scan.json");
    let output = command(&home, &work)
        .args([
            "scan",
            "--quiet",
            "--json",
            json.to_str().expect("json path"),
        ])
        .output()
        .expect("run scan");

    let exit_code = output.status.code().unwrap_or(-1);
    assert!(
        exit_code == 0 || exit_code == 1,
        "scan should exit 0 or 1, got {exit_code}: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json_text = fs::read_to_string(&json).expect("read json");
    assert!(
        !json_text.contains("dbsecret123"),
        "database pw should be redacted:\n{json_text}"
    );
}

#[test]
fn lock_and_diff_do_not_print_url_credentials() {
    let home = temp_dir("lock-redact-home");
    let work = temp_dir("lock-redact-work");

    let userinfo_part = "bob";
    let pw_part = ":pa55w0rd";
    let at_host = String::from("@") + "mcp.example.com/sse";
    let raw_url = format!("http://{userinfo_part}{pw_part}{at_host}");

    fs::create_dir_all(home.join(".cursor")).expect("cursor dir");
    let config = format!(
        r#"{{
  "mcpServers": {{
    "test-server": {{
      "command": "{raw_url}"
    }}
  }}
}}"#
    );
    fs::write(home.join(".cursor/mcp.json"), config).expect("write config");

    let lock_path = work.join("balerx.lock");
    let lock_out = command(&home, &work)
        .args(["lock", "--output", lock_path.to_str().expect("lock path")])
        .output()
        .expect("run lock");
    assert!(
        lock_out.status.success(),
        "lock failed: {}",
        String::from_utf8_lossy(&lock_out.stderr)
    );

    let lock_text = fs::read_to_string(&lock_path).expect("read lock");
    assert!(
        !lock_text.contains("pa55w0rd"),
        "new lockfile leaked credential:\n{lock_text}"
    );

    let rewritten = lock_text.replace("http://mcp.example.com/sse", raw_url.as_str());
    assert!(
        rewritten.contains("pa55w0rd"),
        "expected to restore an old-format command for the compatibility check"
    );
    fs::write(&lock_path, rewritten).expect("write old lockfile");

    let diff_out = command(&home, &work)
        .args(["diff", "--lockfile", lock_path.to_str().expect("lock path")])
        .output()
        .expect("run diff");
    let stdout = String::from_utf8_lossy(&diff_out.stdout);
    let stderr = String::from_utf8_lossy(&diff_out.stderr);
    assert!(
        !stdout.contains("pa55w0rd") && !stderr.contains("pa55w0rd"),
        "diff leaked credential:\n{stdout}\n{stderr}"
    );
    assert!(
        diff_out.status.success(),
        "old lockfile with the same config hash should not report drift:\n{stdout}\n{stderr}"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn written_lockfile_redacts_package_flags_and_inline_shell() {
    let home = temp_dir("lock-written-home");
    let work = temp_dir("lock-written-work");

    let git_user = "guser";
    let git_pw = "Gp1";
    let git_at = String::from("@") + "github.com/org/repo.git";
    let git_url = format!("git+https://{git_user}:{git_pw}{git_at}");

    let tb_user = "tuser";
    let tb_pw = "Tp1";
    let tb_tok = "Tk1";
    let tb_at = String::from("@") + "host.example.com/pkg.tgz";
    let tb_url = format!("https://{tb_user}:{tb_pw}{tb_at}?token={tb_tok}");

    let bx = ["Bx", "Mk1"].concat();
    let cs = "Cs1";
    let at = "At1";
    let au = "Au1";
    let sc = "Sc1";
    let ka = "Ka1";
    let ck = "Ck1";
    let scheme = "Bearer ";
    let shell_script =
        format!("curl -H 'Authorization: {scheme}{bx}' https://api.example.com/sse?token={tb_tok}");
    let shell_command = format!("bash -c 'curl -H \"Authorization: {scheme}{bx}\" https://x'");

    fs::create_dir_all(home.join(".cursor")).expect("cursor dir");
    let config = serde_json::json!({
        "mcpServers": {
            "git-pkg": {
                "command": "npx",
                "args": ["-y", git_url]
            },
            "tarball-pkg": {
                "command": "npx",
                "args": ["-y", tb_url]
            },
            "shell-args": {
                "command": "bash",
                "args": ["-c", shell_script]
            },
            "shell-command": {
                "command": shell_command
            },
            "flags": {
                "command": "tool",
                "args": [
                    "--client-secret", cs,
                    "--access-token", at,
                    "--auth", au,
                    format!("--secret={sc}"),
                    "-H", format!("Authorization: {scheme}{bx}"),
                    "--header", format!("X-Api-Key: {ka}"),
                    "-H", format!("Cookie: sid={ck}")
                ]
            },
            "benign": {
                "command": "psql",
                "args": ["postgres://host:5432/db?authSource=admin&sslmode=require&mode=ro"]
            }
        }
    });
    fs::write(
        home.join(".cursor/mcp.json"),
        serde_json::to_string_pretty(&config).expect("serialize config"),
    )
    .expect("write config");

    let lock_path = work.join("balerx.lock");
    let lock_out = command(&home, &work)
        .args(["lock", "--output", lock_path.to_str().expect("lock path")])
        .output()
        .expect("run lock");
    assert!(
        lock_out.status.success(),
        "lock failed: {}\n{}",
        String::from_utf8_lossy(&lock_out.stdout),
        String::from_utf8_lossy(&lock_out.stderr)
    );

    let lock_text = fs::read_to_string(&lock_path).expect("read lock");
    let git_userinfo = format!("{git_user}:{git_pw}");
    let tb_userinfo = format!("{tb_user}:{tb_pw}");
    for marker in [
        git_pw,
        tb_pw,
        tb_tok,
        bx.as_str(),
        cs,
        at,
        au,
        sc,
        ka,
        ck,
        git_userinfo.as_str(),
        tb_userinfo.as_str(),
    ] {
        assert!(
            !lock_text.contains(marker),
            "written lockfile leaked {marker}:\n{lock_text}"
        );
    }
    assert!(
        lock_text.contains("authSource=admin")
            && lock_text.contains("sslmode=require")
            && lock_text.contains("mode=ro"),
        "benign query params should stay:\n{lock_text}"
    );
    assert!(
        lock_text.contains("github.com/org/repo.git")
            && lock_text.contains("host.example.com/pkg.tgz"),
        "hosts should remain after userinfo redaction:\n{lock_text}"
    );
    assert!(
        !lock_text.contains(&format!("name = \"https://{tb_user}:{tb_pw}\"")),
        "package.name must not be a split userinfo prefix:\n{lock_text}"
    );
}

#[test]
fn package_url_userinfo_is_redacted_in_scan_findings() {
    let home = temp_dir("scan-pkg-home");
    let work = temp_dir("scan-pkg-work");

    let git_user = "guser";
    let git_pw = "Gp1";
    let git_at = String::from("@") + "github.com/o/r.git";
    let git_url = format!("git+https://{git_user}:{git_pw}{git_at}");

    let tb_user = "tuser";
    let tb_pw = "Tp1";
    let tb_tok = "Tk1";
    let tb_at = String::from("@") + "host.example.com/pkg.tgz";
    let tb_url = format!("https://{tb_user}:{tb_pw}{tb_at}?token={tb_tok}");

    fs::create_dir_all(home.join(".cursor")).expect("cursor dir");
    let config = serde_json::json!({
        "mcpServers": {
            "git-pkg": {
                "command": "npx",
                "args": [git_url]
            },
            "tarball-pkg": {
                "command": "npx",
                "args": ["-y", tb_url]
            }
        }
    });
    fs::write(
        home.join(".cursor/mcp.json"),
        serde_json::to_string_pretty(&config).expect("serialize config"),
    )
    .expect("write config");

    let json = work.join("scan.json");
    let sarif = work.join("scan.sarif");
    let html = work.join("scan.html");
    let text_out = command(&home, &work)
        .args([
            "scan",
            "--quiet",
            "--json",
            json.to_str().expect("json path"),
            "--sarif",
            sarif.to_str().expect("sarif path"),
            "--html",
            html.to_str().expect("html path"),
            "--format",
            "text",
        ])
        .output()
        .expect("run text scan");
    let json_out = command(&home, &work)
        .args(["scan", "--quiet", "--format", "json"])
        .output()
        .expect("run json scan");

    let stdout = String::from_utf8_lossy(&text_out.stdout);
    let format_json = String::from_utf8_lossy(&json_out.stdout);
    let json_text = fs::read_to_string(&json).expect("read json");
    let sarif_text = fs::read_to_string(&sarif).expect("read sarif");
    let html_text = fs::read_to_string(&html).expect("read html");

    let git_userinfo = format!("{git_user}:{git_pw}");
    let tb_userinfo = format!("{tb_user}:{tb_pw}");
    for (name, report) in [
        ("terminal", stdout.as_ref()),
        ("format-json", format_json.as_ref()),
        ("json", json_text.as_str()),
        ("sarif", sarif_text.as_str()),
        ("html", html_text.as_str()),
    ] {
        for marker in [
            git_pw,
            tb_pw,
            tb_tok,
            git_userinfo.as_str(),
            tb_userinfo.as_str(),
        ] {
            assert!(
                !report.contains(marker),
                "{name} leaked {marker}:\n{report}"
            );
        }
    }
}

#[test]
fn v015_split_package_lockfile_does_not_drift_or_leak() {
    let home = temp_dir("lock-v015-home");
    let work = temp_dir("lock-v015-work");

    let git_user = "guser";
    let git_pw = "Gp1";
    let git_at = String::from("@") + "github.com/o/r.git";
    let git_url = format!("git+https://{git_user}:{git_pw}{git_at}");

    let tb_user = "tuser";
    let tb_pw = "Tp1";
    let tb_tok = "Tk1";
    let tb_at = String::from("@") + "host.example.com/pkg.tgz";
    let tb_url = format!("https://{tb_user}:{tb_pw}{tb_at}?token={tb_tok}");

    fs::create_dir_all(home.join(".cursor")).expect("cursor dir");
    let config = serde_json::json!({
        "mcpServers": {
            "git-pkg": {
                "command": "npx",
                "args": [git_url]
            },
            "tarball-pkg": {
                "command": "npx",
                "args": ["-y", tb_url]
            }
        }
    });
    fs::write(
        home.join(".cursor/mcp.json"),
        serde_json::to_string_pretty(&config).expect("serialize config"),
    )
    .expect("write config");

    let lock_path = work.join("balerx.lock");
    let lock_out = command(&home, &work)
        .args(["lock", "--output", lock_path.to_str().expect("lock path")])
        .output()
        .expect("run lock");
    assert!(
        lock_out.status.success(),
        "lock failed: {}",
        String::from_utf8_lossy(&lock_out.stderr)
    );

    let current = fs::read_to_string(&lock_path).expect("read lock");
    let git_block =
        "[mcp_servers.package]\nname = \"git+https://github.com/o/r.git\"\nversion = \"\"";
    let git_old = format!(
        "[mcp_servers.package]\nname = \"git+https://{git_user}:{git_pw}\"\nversion = \"github.com/o/r.git\""
    );
    let tb_block =
        "[mcp_servers.package]\nname = \"https://host.example.com/pkg.tgz?token=[REDACTED]\"\nversion = \"\"";
    let tb_old = format!(
        "[mcp_servers.package]\nname = \"https://{tb_user}:{tb_pw}\"\nversion = \"host.example.com/pkg.tgz?token={tb_tok}\""
    );
    let rewritten = current
        .replace(git_block, &git_old)
        .replace(tb_block, &tb_old);
    assert!(
        rewritten.contains(&format!("name = \"git+https://{git_user}:{git_pw}\""))
            && rewritten.contains(&format!("token={tb_tok}")),
        "expected v0.1.5 split package fields:\n{rewritten}\nfrom:\n{current}"
    );
    fs::write(&lock_path, rewritten).expect("write old lockfile");

    let diff_out = command(&home, &work)
        .args(["diff", "--lockfile", lock_path.to_str().expect("lock path")])
        .output()
        .expect("run diff");
    let stdout = String::from_utf8_lossy(&diff_out.stdout);
    let stderr = String::from_utf8_lossy(&diff_out.stderr);
    assert!(
        diff_out.status.success(),
        "v0.1.5 lockfile should not report drift:\n{stdout}\n{stderr}"
    );
    assert!(
        !stdout.contains("version changed") && !stderr.contains("version changed"),
        "should not report version drift:\n{stdout}\n{stderr}"
    );
    for marker in [git_pw, tb_pw, tb_tok] {
        assert!(
            !stdout.contains(marker) && !stderr.contains(marker),
            "diff leaked {marker}:\n{stdout}\n{stderr}"
        );
    }
}
