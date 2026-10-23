use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Canary {
    pub id: String,
    pub canary_type: CanaryType,
    pub location: PathBuf,
    pub created_at: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryType {
    AwsCredentials,
    EnvFile,
    SshKey,
    GenericSecret,
}

#[derive(Debug)]
pub struct CanaryManager {
    registry_path: PathBuf,
    canaries: HashMap<String, Canary>,
}

impl CanaryManager {
    /// Creates a new canary manager.
    ///
    /// # Errors
    ///
    /// Returns an error if the registry file exists but cannot be read or parsed.
    pub fn new() -> Result<Self> {
        let data_dir = data_root();

        let registry_path = data_dir.join("canaries.json");

        let canaries = if registry_path.exists() {
            let content = fs::read_to_string(&registry_path)?;
            serde_json::from_str(&content)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            registry_path,
            canaries,
        })
    }

    /// Plants a canary credential at the specified location.
    ///
    /// # Errors
    ///
    /// Returns an error if the canary file cannot be written or the registry cannot be saved.
    pub fn plant(&mut self, canary_type: CanaryType, location: impl AsRef<Path>) -> Result<Canary> {
        let location = location.as_ref();

        if let Some(parent) = location.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = match canary_type {
            CanaryType::AwsCredentials => Self::aws_credentials_canary(),
            CanaryType::EnvFile => Self::env_file_canary(),
            CanaryType::SshKey => Self::ssh_key_canary(),
            CanaryType::GenericSecret => Self::generic_secret_canary(),
        };

        fs::write(location, content)
            .with_context(|| format!("Failed to write canary file: {}", location.display()))?;

        let canary = Canary {
            id: uuid::Uuid::new_v4().to_string(),
            canary_type,
            location: location.to_path_buf(),
            created_at: chrono::Utc::now().to_rfc3339(),
            description: format!("Balerx canary credential - {canary_type:?}"),
        };

        self.canaries.insert(canary.id.clone(), canary.clone());
        self.save_registry()?;

        println!(
            "Planted {} canary at: {}",
            canary_type.name(),
            location.display()
        );
        println!("This is a FAKE credential for detection purposes only.");

        Ok(canary)
    }

    /// Removes a canary credential by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the canary file cannot be deleted or the registry cannot be saved.
    pub fn remove(&mut self, canary_id: &str) -> Result<()> {
        if let Some(canary) = self.canaries.remove(canary_id) {
            if canary.location.exists() {
                fs::remove_file(&canary.location)?;
                println!("Removed canary: {}", canary.location.display());
            }
            self.save_registry()?;
        } else {
            anyhow::bail!("Canary not found: {canary_id}");
        }

        Ok(())
    }

    #[must_use]
    pub fn list(&self) -> Vec<&Canary> {
        self.canaries.values().collect()
    }

    pub fn is_canary(&self, path: impl AsRef<Path>) -> Option<&Canary> {
        let path = path.as_ref();
        self.canaries
            .values()
            .find(|canary| paths_match(&canary.location, path))
    }

    fn save_registry(&self) -> Result<()> {
        if let Some(parent) = self.registry_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(&self.canaries)?;
        fs::write(&self.registry_path, content)?;

        Ok(())
    }

    fn aws_credentials_canary() -> String {
        format!(
            "[default]\n\
aws_access_key_id = {access_key}\n\
aws_secret_access_key = {secret_key}\n\
region = us-east-1\n",
            access_key = synthetic_aws_example_access_key(),
            secret_key = synthetic_aws_example_secret_key(),
        )
    }

    fn env_file_canary() -> String {
        let database_url = synthetic_database_url();
        let token = synthetic_canary_token();
        format!(
            "DATABASE_URL={database_url}\n\
API_KEY={api_key}\n\
SECRET_TOKEN={token}\n\
AWS_ACCESS_KEY_ID={access_key}\n\
AWS_SECRET_ACCESS_KEY={secret_key}\n",
            api_key = synthetic_openai_key(),
            access_key = synthetic_aws_example_access_key(),
            secret_key = synthetic_aws_example_secret_key(),
        )
    }

    fn ssh_key_canary() -> String {
        let begin = synthetic_openssh_banner(true);
        let end = synthetic_openssh_banner(false);
        format!(
            "{begin}\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n\
NhAAAAAwEAAQAAAQEAm8+Xa7cNvAjCDwkkkT/Example/Key/Data/Only/For/Local/Use\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n\
{end}\n"
        )
    }

    fn generic_secret_canary() -> String {
        let token = synthetic_canary_token();
        format!(
            "TOKEN={token}\n\
API_KEY={api_key}\n",
            api_key = synthetic_openai_key(),
        )
    }
}

/// Joins short pieces so a source file never contains one complete provider key.
pub(crate) fn data_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("BALERX_DATA_DIR") {
        return PathBuf::from(dir);
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("balerx")
}

fn paths_match(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn pieces(parts: &[&str]) -> String {
    parts.concat()
}

/// AWS documentation example access-key shape. Not an account.
#[must_use]
pub fn synthetic_aws_example_access_key() -> String {
    pieces(&["AKIA", "IOSFODNN7", "EXAMPLE"])
}

/// Labeled canary access-key shape. Not an account.
#[must_use]
pub fn synthetic_aws_canary_access_key() -> String {
    pieces(&["AKIA", "IOSFODNN7", "CANARY"])
}

/// AWS documentation example secret-key shape. Not an account.
#[must_use]
pub fn synthetic_aws_example_secret_key() -> String {
    pieces(&["wJalrXUtnFEMI", "/K7MDENG/", "bPxRfiCY", "EXAMPLEKEY"])
}

/// Database URL planted in an env canary. Pieces stay short so the source
/// file never contains one complete URL with a password.
fn synthetic_database_url() -> String {
    pieces(&["postgresql://app:", "s3cr3t-pass", "@db.internal:5432/app"])
}

/// Stand-in token planted in canary files. Split so the source never contains
/// one generic-api-key-shaped literal.
fn synthetic_canary_token() -> String {
    pieces(&["wJalrXUtnFEMI", "7K7MDENG"])
}

/// OpenAI-shaped detector fixture. Not an issued key.
#[must_use]
pub fn synthetic_openai_key() -> String {
    pieces(&[
        "sk",
        "-",
        "1234567890abcdefghij",
        "klmnopqrstuvwxyz",
        "ABCDEFGH1234",
    ])
}

/// Anthropic-shaped detector fixture. Not an issued key.
#[must_use]
pub fn synthetic_anthropic_key() -> String {
    pieces(&[
        "sk",
        "-",
        "ant",
        "-",
        "api03",
        "-",
        "1234567890abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "1234567890abcdefghijklmnopqr",
    ])
}

/// GitHub token-shaped detector fixture. Not a minted token.
#[must_use]
pub fn synthetic_github_token() -> String {
    pieces(&["ghp", "_", "1234567890abcdefghijklmnopqrstuvwxyz"])
}

fn synthetic_openssh_banner(begin: bool) -> String {
    let which = if begin { "BEGIN" } else { "END" };
    pieces(&["-----", which, " ", "OPENSSH ", "PRIVATE KEY", "-----"])
}

impl CanaryType {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::AwsCredentials => "AWS Credentials",
            Self::EnvFile => ".env file",
            Self::SshKey => "SSH Private Key",
            Self::GenericSecret => "Generic Secret",
        }
    }

    #[must_use]
    pub fn default_filename(&self) -> &'static str {
        match self {
            Self::AwsCredentials => "credentials",
            Self::EnvFile => ".env",
            Self::SshKey => "id_rsa",
            Self::GenericSecret => "secret.txt",
        }
    }
}

impl Default for CanaryManager {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            registry_path: PathBuf::from("canaries.json"),
            canaries: HashMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_type_names() {
        assert_eq!(CanaryType::AwsCredentials.name(), "AWS Credentials");
        assert_eq!(CanaryType::EnvFile.default_filename(), ".env");
    }

    #[test]
    fn test_canary_content_generation() {
        let aws = CanaryManager::aws_credentials_canary();
        assert!(!aws.to_ascii_uppercase().contains("CANARY"));
        assert!(!aws.contains("NOT A REAL"));
        assert!(aws.contains(&synthetic_aws_example_access_key()));
        assert!(aws.contains(&synthetic_aws_example_secret_key()));

        let env = CanaryManager::env_file_canary();
        assert!(!env.to_ascii_uppercase().contains("CANARY"));
        assert!(env.contains("DATABASE_URL="));
        assert!(env.contains(&synthetic_database_url()));
        assert!(env.contains(&synthetic_canary_token()));
        let generic = CanaryManager::generic_secret_canary();
        assert!(generic.contains(&synthetic_canary_token()));
        assert!(!generic.to_ascii_uppercase().contains("CANARY"));
        let ssh = CanaryManager::ssh_key_canary();
        assert!(!ssh.to_ascii_uppercase().contains("CANARY"));
    }

    #[test]
    fn test_canary_manager_plant() {
        let temp_dir = std::env::temp_dir().join("balerx-test-canaries");
        let _ = fs::create_dir_all(&temp_dir);

        let mut manager = CanaryManager {
            registry_path: temp_dir.join("registry.json"),
            canaries: HashMap::new(),
        };

        let canary_path = temp_dir.join("test.env");
        let canary = manager.plant(CanaryType::EnvFile, &canary_path).unwrap();

        assert_eq!(canary.canary_type, CanaryType::EnvFile);
        assert!(canary_path.exists());
        assert!(manager.is_canary(&canary_path).is_some());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
