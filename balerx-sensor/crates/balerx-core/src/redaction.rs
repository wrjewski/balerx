use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static SECRET_QUERY_PARAMS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "token",
        "key",
        "secret",
        "password",
        "passwd",
        "pwd",
        "auth",
        "authorization",
        "signature",
        "sig",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "api-key",
        "credential",
        "credentials",
        "bearer",
        "jwt",
        "code",
        "sessionid",
        "session_id",
    ]
    .iter()
    .copied()
    .collect()
});

static BENIGN_EXACT_PARAMS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    ["authSource", "authsource", "sslmode", "mode"]
        .iter()
        .copied()
        .collect()
});

static URL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(r"(?i)", r"([a-z][a-z0-9+.-]*://)", r"([^\s]*)")).expect("url regex")
});

#[must_use]
pub fn redact_url(url: &str) -> String {
    let after_schemes = URL_REGEX
        .replace_all(url, |caps: &regex::Captures| {
            let scheme = caps.get(1).map_or("", |m| m.as_str());
            let rest = caps.get(2).map_or("", |m| m.as_str());

            let fragment_pos = rest.find('#');
            let before_fragment = if let Some(pos) = fragment_pos {
                &rest[..pos]
            } else {
                rest
            };

            let authority_end = before_fragment
                .find(['/', '?'])
                .unwrap_or(before_fragment.len());
            if let Some(at_pos) = before_fragment[..authority_end].rfind('@') {
                let after_at = &before_fragment[at_pos + 1..];

                let path_pos = after_at.find('/');
                let query_pos = after_at.find('?');
                let host_end = [path_pos, query_pos]
                    .iter()
                    .filter_map(|&p| p)
                    .min()
                    .unwrap_or(after_at.len());

                let host = &after_at[..host_end];
                let path_and_query = &after_at[host_end..];

                let (query_str, fragment) = if let Some(frag_pos) = fragment_pos {
                    let q_part = &rest[at_pos + 1 + host_end..frag_pos];
                    (q_part, &rest[frag_pos..])
                } else {
                    (path_and_query, "")
                };

                let redacted_query = if query_str.starts_with('?') {
                    redact_query_string(query_str)
                } else if query_str.starts_with('/') {
                    let parts: Vec<&str> = query_str.splitn(2, '?').collect();
                    if parts.len() == 2 {
                        let redacted_q = redact_query_string(&format!("?{}", parts[1]));
                        format!("{}?{}", parts[0], &redacted_q[1..])
                    } else {
                        query_str.to_string()
                    }
                } else {
                    query_str.to_string()
                };

                let redacted_fragment = if fragment.is_empty() {
                    String::new()
                } else {
                    redact_fragment(fragment)
                };

                format!("{scheme}{host}{redacted_query}{redacted_fragment}")
            } else {
                let query_pos = before_fragment.find('?');
                let path_pos = before_fragment.find('/');

                let authority_end = [query_pos, path_pos]
                    .iter()
                    .filter_map(|&p| p)
                    .min()
                    .unwrap_or(before_fragment.len());

                let authority = &before_fragment[..authority_end];
                let rest_part = &before_fragment[authority_end..];

                let fragment = if let Some(frag_pos) = fragment_pos {
                    &rest[frag_pos..]
                } else {
                    ""
                };

                let (path, query_part) = if let Some(q_pos) = rest_part.find('?') {
                    (&rest_part[..q_pos], &rest_part[q_pos..])
                } else {
                    (rest_part, "")
                };

                let redacted_query = if query_part.is_empty() {
                    String::new()
                } else {
                    redact_query_string(query_part)
                };

                let redacted_fragment = if fragment.is_empty() {
                    String::new()
                } else {
                    redact_fragment(fragment)
                };

                format!("{scheme}{authority}{path}{redacted_query}{redacted_fragment}")
            }
        })
        .to_string();
    redact_schemeless_queries(&after_schemes)
}

fn redact_schemeless_queries(text: &str) -> String {
    let Some(q_pos) = text.find('?') else {
        return text.to_string();
    };
    if text[..q_pos].contains("://") {
        return text.to_string();
    }

    let after = &text[q_pos..];
    let hash_pos = after.find('#');
    let (query, fragment) = if let Some(pos) = hash_pos {
        (&after[..pos], &after[pos..])
    } else {
        (after, "")
    };

    let redacted_query = redact_query_string(query);
    let redacted_query = if redacted_query.is_empty() {
        String::new()
    } else if redacted_query == query && !query[1..].contains('=') {
        "?[REDACTED]".to_string()
    } else {
        redacted_query
    };

    let redacted_fragment = if fragment.is_empty() {
        String::new()
    } else {
        redact_fragment(fragment)
    };

    format!("{}{redacted_query}{redacted_fragment}", &text[..q_pos])
}

fn percent_decode(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push(ch);
            result.push_str(&hex);
        } else {
            result.push(ch);
        }
    }
    result
}

fn is_secret_param(key: &str) -> bool {
    let decoded = percent_decode(key);
    let key_lower = decoded.to_ascii_lowercase();

    if BENIGN_EXACT_PARAMS.contains(key_lower.as_str()) {
        return false;
    }

    SECRET_QUERY_PARAMS
        .iter()
        .any(|secret_key| key_lower.contains(secret_key))
}

fn redact_query_string(query_str: &str) -> String {
    if !query_str.starts_with('?') {
        return String::new();
    }

    let params: Vec<String> = query_str[1..]
        .split(&['&', ';'])
        .map(|param| {
            if let Some((key, _value)) = param.split_once('=') {
                if is_secret_param(key) {
                    format!("{key}=[REDACTED]")
                } else {
                    param.to_string()
                }
            } else {
                param.to_string()
            }
        })
        .collect();

    if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    }
}

fn redact_fragment(fragment: &str) -> String {
    if !fragment.starts_with('#') {
        return String::new();
    }

    let params: Vec<String> = fragment[1..]
        .split('&')
        .map(|param| {
            if let Some((key, _value)) = param.split_once('=') {
                if is_secret_param(key) {
                    format!("{key}=[REDACTED]")
                } else {
                    param.to_string()
                }
            } else {
                param.to_string()
            }
        })
        .collect();

    if params.is_empty() {
        String::new()
    } else {
        format!("#{}", params.join("&"))
    }
}

#[must_use]
pub fn redact_evidence_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(redact_url(s)),
        serde_json::Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (k, v) in map {
                redacted.insert(k.clone(), redact_evidence_value(v));
            }
            serde_json::Value::Object(redacted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(redact_evidence_value).collect())
        }
        other => other.clone(),
    }
}

static SENSITIVE_HEADER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(Authorization\s*:\s*Bearer\s+[^\s'"]+|Authorization\s*:\s*[^\s'"]+|Cookie\s*:\s*[^\s'"]+|X-Api-Key\s*:\s*[^\s'"]+|X-Auth[A-Za-z0-9-]*\s*:\s*[^\s'"]+)"#)
        .expect("header regex")
});

static BEARER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\bBearer\s+[^\s'"]+"#).expect("bearer regex"));

const SECRET_FLAG_WORDS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "key",
    "auth",
    "credential",
    "cookie",
];

/// Redact a command string (including `bash -c '...'` as one field).
#[must_use]
pub fn redact_command_line(command: &str) -> String {
    redact_text(command)
}

/// Redact `command` and `args` together so a shell in `command` still
/// redacts the `-c` payload that lives in `args`.
#[must_use]
pub fn redact_stdio(command: &str, args: &[String]) -> (String, Vec<String>) {
    (
        redact_command_line(command),
        redact_command_args_with_command(command, args),
    )
}

#[must_use]
pub fn redact_command_args(args: &[String]) -> Vec<String> {
    redact_command_args_with_command("", args)
}

fn redact_command_args_with_command(command: &str, args: &[String]) -> Vec<String> {
    let command_is_shell = is_shell_base(command);
    let mut result = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];

        if arg == "-e" || arg == "--env" {
            result.push(arg.clone());
            if i + 1 < args.len() {
                result.push(redact_env_assignment(&args[i + 1]));
                i += 2;
                continue;
            }
        }

        if arg == "-H" || arg == "--header" {
            result.push(arg.clone());
            if i + 1 < args.len() {
                result.push(redact_header_value(&args[i + 1]));
                i += 2;
                continue;
            }
        }

        if let Some(name) = secret_flag_equals(arg) {
            result.push(format!("{name}=[REDACTED]"));
            i += 1;
            continue;
        }

        if is_secret_long_flag(arg) {
            result.push(arg.clone());
            if i + 1 < args.len() {
                result.push("[REDACTED]".to_string());
                i += 2;
                continue;
            }
        }

        if is_shell_word(arg) && i + 1 < args.len() && args[i + 1] == "-c" {
            result.push(arg.clone());
            result.push("-c".to_string());
            if i + 2 < args.len() {
                result.push(redact_text(&args[i + 2]));
                i += 3;
                continue;
            }
        }

        if command_is_shell && arg == "-c" && i + 1 < args.len() {
            result.push(arg.clone());
            result.push(redact_text(&args[i + 1]));
            i += 2;
            continue;
        }

        result.push(redact_text(arg));
        i += 1;
    }
    result
}

fn is_shell_word(word: &str) -> bool {
    let name = word.rsplit(['/', '\\']).next().unwrap_or(word);
    matches!(name, "bash" | "sh" | "zsh" | "pwsh" | "powershell")
}

fn is_shell_base(command: &str) -> bool {
    command.split_whitespace().next().is_some_and(is_shell_word)
}

fn redact_text(text: &str) -> String {
    redact_sensitive_inline(&redact_url(text))
}

fn redact_sensitive_inline(text: &str) -> String {
    let without_headers = SENSITIVE_HEADER_RE.replace_all(text, |caps: &regex::Captures| {
        let matched = caps.get(0).map_or("", |m| m.as_str());
        header_redaction_label(matched)
    });
    BEARER_RE
        .replace_all(&without_headers, "Bearer [REDACTED]")
        .to_string()
}

fn header_redaction_label(header: &str) -> String {
    let Some((name, value)) = header.split_once(':') else {
        return "[REDACTED]".to_string();
    };
    let trimmed = value.trim();
    if name.trim().eq_ignore_ascii_case("authorization")
        && trimmed.to_ascii_lowercase().starts_with("bearer ")
    {
        format!("{}: Bearer [REDACTED]", name.trim())
    } else {
        format!("{}: [REDACTED]", name.trim())
    }
}

fn redact_header_value(header: &str) -> String {
    if let Some((name, _)) = header.split_once(':') {
        if is_sensitive_header_name(name) {
            return header_redaction_label(header);
        }
    }
    redact_text(header)
}

fn is_sensitive_header_name(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    n == "authorization" || n == "cookie" || n == "x-api-key" || n.starts_with("x-auth")
}

fn redact_env_assignment(value: &str) -> String {
    if let Some((key, _val)) = value.split_once('=') {
        if is_secret_param(key) {
            return format!("{key}=[REDACTED]");
        }
    }
    redact_text(value)
}

fn flag_name_is_secret(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if BENIGN_EXACT_PARAMS.contains(lower.as_str()) {
        return false;
    }
    SECRET_FLAG_WORDS.iter().any(|word| lower.contains(word))
}

fn is_secret_long_flag(arg: &str) -> bool {
    let Some(name) = arg.strip_prefix("--") else {
        return false;
    };
    if name.contains('=') {
        return false;
    }
    flag_name_is_secret(name)
}

fn secret_flag_equals(arg: &str) -> Option<&str> {
    let rest = arg.strip_prefix("--")?;
    let (name, _value) = rest.split_once('=')?;
    if flag_name_is_secret(name) {
        Some(&arg[..name.len() + 2])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_userinfo() {
        let parts = ["http://bob:", "pa55w0rd", "@mcp.example.com/sse"];
        let url = parts.concat();
        let redacted = redact_url(&url);
        assert_eq!(redacted, "http://mcp.example.com/sse");
        assert!(!redacted.contains("bob"));
        assert!(!redacted.contains("pa55w0rd"));
    }

    #[test]
    fn redact_userinfo_keeps_at_in_path() {
        let parts = ["https://user:", "pw", "@host/pkg@latest"];
        let url = parts.concat();
        let redacted = redact_url(&url);
        assert_eq!(redacted, "https://host/pkg@latest");
        assert!(!redacted.contains("user"));
        assert!(!redacted.contains(":pw@"));
        assert!(!redacted.contains("pw@"));
    }

    #[test]
    fn redact_empty_username() {
        let parts = ["redis://:", "mypassword", "@host:6379/0"];
        let url = parts.concat();
        let redacted = redact_url(&url);
        assert_eq!(redacted, "redis://host:6379/0");
        assert!(!redacted.contains("mypassword"));
    }

    #[test]
    fn redact_password_with_at_sign() {
        let parts = ["https://u:", "abc@ssTAIL", "@host/path"];
        let url = parts.concat();
        let redacted = redact_url(&url);
        assert_eq!(redacted, "https://host/path");
        assert!(!redacted.contains("abc@ssTAIL"));
        assert!(!redacted.contains("@ssTAIL"));
    }

    #[test]
    fn slash_ends_authority_so_embedded_slash_is_path() {
        let parts = ["https://u:", "PW/x", "@host/path"];
        let url = parts.concat();
        let redacted = redact_url(&url);
        // A '/' ends the authority. This non-RFC userinfo becomes a path and
        // stays, matching the documented path-only limitation.
        assert_eq!(redacted, url);
        assert!(redacted.contains("PW/x"));
    }

    #[test]
    fn redact_fragment_with_access_token() {
        let parts = [
            "https://example.com/callback#",
            "access_token=SECRET123&state=xyz",
        ];
        let url = parts.concat();
        let redacted = redact_url(&url);
        assert!(!redacted.contains("SECRET123"));
        assert!(redacted.contains("access_token=[REDACTED]"));
        assert!(redacted.contains("state=xyz"));
    }

    #[test]
    fn redact_query_with_semicolon_separator() {
        let parts = [
            "https://api.example.com/path?mode=ro;",
            "token=LIVEKEY;debug=true",
        ];
        let url = parts.concat();
        let redacted = redact_url(&url);
        assert!(!redacted.contains("LIVEKEY"));
        assert!(redacted.contains("token=[REDACTED]"));
        assert!(redacted.contains("mode=ro"));
        assert!(redacted.contains("debug=true"));
    }

    #[test]
    fn redact_percent_encoded_token_param() {
        let parts = ["https://api.example.com?t%6Fken=", "SECRET"];
        let url = parts.concat();
        let redacted = redact_url(&url);
        assert!(!redacted.contains("SECRET"));
        assert!(redacted.contains("t%6Fken=[REDACTED]"));
    }

    #[test]
    fn redact_bearer_param() {
        let parts = ["https://api.example.com?", "bearer=abc123"];
        let url = parts.concat();
        let redacted = redact_url(&url);
        assert!(!redacted.contains("abc123"));
        assert!(redacted.contains("bearer=[REDACTED]"));
    }

    #[test]
    fn redact_jwt_param() {
        let parts = ["https://api.example.com?", "jwt=eyJhbGc"];
        let url = parts.concat();
        let redacted = redact_url(&url);
        assert!(!redacted.contains("eyJhbGc"));
        assert!(redacted.contains("jwt=[REDACTED]"));
    }

    #[test]
    fn redact_code_param() {
        let parts = [
            "https://oauth.example.com/callback?",
            "code=AUTH123&state=xyz",
        ];
        let url = parts.concat();
        let redacted = redact_url(&url);
        assert!(!redacted.contains("AUTH123"));
        assert!(redacted.contains("code=[REDACTED]"));
        assert!(redacted.contains("state=xyz"));
    }

    #[test]
    fn redact_sessionid_param() {
        let parts = ["https://app.example.com?", "sessionid=abc123"];
        let url = parts.concat();
        let redacted = redact_url(&url);
        assert!(!redacted.contains("abc123"));
        assert!(redacted.contains("sessionid=[REDACTED]"));
    }

    #[test]
    fn do_not_redact_authsource() {
        let url = "mongodb://host:27017/db?authSource=admin&replicaSet=rs0";
        let redacted = redact_url(url);
        assert_eq!(redacted, url);
        assert!(redacted.contains("authSource=admin"));
    }

    #[test]
    fn do_not_redact_sslmode() {
        let url = "postgres://host:5432/db?sslmode=require&mode=ro";
        let redacted = redact_url(url);
        assert_eq!(redacted, url);
        assert!(redacted.contains("sslmode=require"));
        assert!(redacted.contains("mode=ro"));
    }

    #[test]
    fn redact_secret_query_params() {
        let parts = [
            "https://mcp.example.com/sse?mode=ro&token=",
            "LIVEKEYXYZ123",
            "&debug=true",
        ];
        let url = parts.concat();
        let redacted = redact_url(&url);
        assert!(redacted.contains("mode=ro"));
        assert!(redacted.contains("debug=true"));
        assert!(!redacted.contains("LIVEKEYXYZ123"));
        assert!(redacted.contains("token=[REDACTED]"));
    }

    #[test]
    fn redact_combined_userinfo_and_query() {
        let parts = [
            "http://user:",
            "pass",
            "@api.example.com/path?api_key=SECRET123&limit=10",
        ];
        let url = parts.concat();
        let redacted = redact_url(&url);
        assert!(!redacted.contains("user"));
        assert!(!redacted.contains("pass"));
        assert!(!redacted.contains("SECRET123"));
        assert!(redacted.contains("limit=10"));
        assert!(redacted.contains("api_key=[REDACTED]"));
    }

    #[test]
    fn preserve_benign_urls() {
        let url = "https://example.com/path?mode=ro&limit=100";
        let redacted = redact_url(url);
        assert_eq!(redacted, url);
    }

    #[test]
    fn redact_authorization_param() {
        let parts = [
            "https://api.example.com?authorization=Bearer%20",
            "token123",
        ];
        let url = parts.concat();
        let redacted = redact_url(&url);
        assert!(!redacted.contains("token123"));
        assert!(redacted.contains("authorization=[REDACTED]"));
    }

    #[test]
    fn handle_non_urls() {
        let text = "regular text with no URLs";
        let redacted = redact_url(text);
        assert_eq!(redacted, text);
    }

    #[test]
    fn redact_json_evidence() {
        let parts = ["http://admin:", "secret", "@db.example.com"];
        let url = parts.concat();
        let evidence = serde_json::json!({
            "server": "test",
            "url": url,
            "nested": {
                "another_url": url
            }
        });

        let redacted = redact_evidence_value(&evidence);
        let redacted_str = redacted.to_string();
        assert!(!redacted_str.contains("admin"));
        assert!(!redacted_str.contains("secret"));
        assert!(redacted_str.contains("db.example.com"));
    }

    #[test]
    fn redact_command_token_flag() {
        let args = vec![
            "curl".to_string(),
            "--token".to_string(),
            "SECRET123".to_string(),
        ];
        let redacted = redact_command_args(&args);
        assert_eq!(redacted.len(), 3);
        assert_eq!(redacted[0], "curl");
        assert_eq!(redacted[1], "--token");
        assert_eq!(redacted[2], "[REDACTED]");
    }

    #[test]
    fn redact_command_password_equals() {
        let args = vec!["psql".to_string(), "--password=SECRET".to_string()];
        let redacted = redact_command_args(&args);
        assert_eq!(redacted.len(), 2);
        assert_eq!(redacted[0], "psql");
        assert_eq!(redacted[1], "--password=[REDACTED]");
        assert!(!redacted[1].contains("SECRET"));
    }

    #[test]
    fn redact_command_header_authorization() {
        let scheme = "Bearer ";
        let value = "SECRET123";
        let args = vec![
            "curl".to_string(),
            "--header".to_string(),
            format!("Authorization: {scheme}{value}"),
        ];
        let redacted = redact_command_args(&args);
        assert_eq!(redacted.len(), 3);
        assert_eq!(redacted[0], "curl");
        assert_eq!(redacted[1], "--header");
        assert_eq!(redacted[2], "Authorization: Bearer [REDACTED]");
        assert!(!redacted[2].contains("SECRET123"));
    }

    #[test]
    fn redact_command_env_var_secret() {
        let args = vec![
            "docker".to_string(),
            "run".to_string(),
            "-e".to_string(),
            "API_KEY=SECRET123".to_string(),
        ];
        let redacted = redact_command_args(&args);
        assert_eq!(redacted.len(), 4);
        assert_eq!(redacted[3], "API_KEY=[REDACTED]");
        assert!(!redacted[3].contains("SECRET123"));
    }

    #[test]
    fn redact_command_env_var_benign() {
        let args = vec![
            "docker".to_string(),
            "run".to_string(),
            "-e".to_string(),
            "DEBUG=true".to_string(),
        ];
        let redacted = redact_command_args(&args);
        assert_eq!(redacted.len(), 4);
        assert_eq!(redacted[3], "DEBUG=true");
    }

    #[test]
    fn redact_bash_c_bearer() {
        let scheme = "Bearer ";
        let value = "SECRET123";
        let script = format!("curl -H 'Authorization: {scheme}{value}' https://api.example.com");
        let args = vec!["bash".to_string(), "-c".to_string(), script];
        let redacted = redact_command_args(&args);
        assert_eq!(redacted.len(), 3);
        assert!(!redacted[2].contains("SECRET123"));
        assert!(redacted[2].contains("Bearer [REDACTED]"));
    }

    #[test]
    fn redact_git_url_in_args() {
        let parts = ["git+https://user:", "token123", "@github.com/org/repo.git"];
        let url = parts.concat();
        let args = vec!["npm".to_string(), "install".to_string(), url];
        let redacted = redact_command_args(&args);
        assert!(!redacted[2].contains("token123"));
        assert!(redacted[2].contains("github.com/org/repo.git"));
    }

    #[test]
    fn redact_shell_c_when_command_is_the_shell() {
        let value = ["Bx", "Mk1"].concat();
        let script = format!("curl -H 'Authorization: Bearer {value}' https://api.example.com");
        let args = vec!["-c".to_string(), script];
        let redacted = redact_stdio("bash", &args).1;
        assert!(!redacted[1].contains(&value));
        assert!(redacted[1].contains("Bearer [REDACTED]"));
    }

    #[test]
    fn redact_command_line_bash_c_string() {
        let value = ["Bx", "Mk1"].concat();
        let command = format!("bash -c 'curl -H \"Authorization: Bearer {value}\" https://x'");
        let redacted = redact_command_line(&command);
        assert!(!redacted.contains(&value));
        assert!(redacted.contains("Bearer [REDACTED]"));
        assert!(
            redacted.contains("\"Authorization: Bearer [REDACTED]\""),
            "closing quote should stay: {redacted}"
        );
    }

    #[test]
    fn redact_schemeless_query_params() {
        let marker = "Tk1";
        let fragment = format!("host.example.com/pkg.tgz?token={marker}&mode=ro");
        let redacted = redact_url(&fragment);
        assert!(!redacted.contains(marker));
        assert!(redacted.contains("token=[REDACTED]"));
        assert!(redacted.contains("mode=ro"));
        assert!(redacted.contains("host.example.com/pkg.tgz"));
    }

    #[test]
    fn redact_generic_secret_flags() {
        let args = vec![
            "tool".to_string(),
            "--client-secret".to_string(),
            "Cs1".to_string(),
            "--access-token".to_string(),
            "At1".to_string(),
            "--auth".to_string(),
            "Au1".to_string(),
            "--secret=Sc1".to_string(),
        ];
        let redacted = redact_command_args(&args);
        assert_eq!(
            redacted,
            vec![
                "tool".to_string(),
                "--client-secret".to_string(),
                "[REDACTED]".to_string(),
                "--access-token".to_string(),
                "[REDACTED]".to_string(),
                "--auth".to_string(),
                "[REDACTED]".to_string(),
                "--secret=[REDACTED]".to_string(),
            ]
        );
    }

    #[test]
    fn redact_header_short_and_named_flags() {
        let scheme = "Bearer ";
        let bx = ["Bx", "Mk1"].concat();
        let args = vec![
            "curl".to_string(),
            "-H".to_string(),
            format!("Authorization: {scheme}{bx}"),
            "--header".to_string(),
            "X-Api-Key: Ka1".to_string(),
            "-H".to_string(),
            "Cookie: sid=Ck1".to_string(),
        ];
        let redacted = redact_command_args(&args);
        assert_eq!(redacted[2], "Authorization: Bearer [REDACTED]");
        assert_eq!(redacted[4], "X-Api-Key: [REDACTED]");
        assert_eq!(redacted[6], "Cookie: [REDACTED]");
    }

    #[test]
    fn keep_benign_query_params_in_args() {
        let url = "postgres://host:5432/db?authSource=admin&sslmode=require&mode=ro";
        let redacted = redact_command_args(&[url.to_string()]);
        assert_eq!(redacted[0], url);
    }
}
