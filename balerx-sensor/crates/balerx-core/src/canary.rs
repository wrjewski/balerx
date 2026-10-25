use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static FORCE_WRITE_ERR: Cell<bool> = const { Cell::new(false) };
}

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
        Self::new_from_path(&registry_path)
    }

    fn new_from_path(registry_path: &Path) -> Result<Self> {
        let canaries = if registry_path.exists() {
            let content = fs::read_to_string(registry_path)?;
            serde_json::from_str(&content)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            registry_path: registry_path.to_path_buf(),
            canaries,
        })
    }

    /// Plants a canary credential at the specified location.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The target file already exists and `force` is false
    /// - The target or any ancestor component is a symlink (always refused, even with `--force`)
    /// - The canary file cannot be written
    /// - The registry cannot be saved
    pub fn plant(
        &mut self,
        canary_type: CanaryType,
        location: impl AsRef<Path>,
        force: bool,
    ) -> Result<Canary> {
        let location = location.as_ref();
        let existed_before = Self::prepare_plant_location(location, force)?;

        let content = match canary_type {
            CanaryType::AwsCredentials => Self::aws_credentials_canary(),
            CanaryType::EnvFile => Self::env_file_canary(),
            CanaryType::SshKey => Self::ssh_key_canary(),
            CanaryType::GenericSecret => Self::generic_secret_canary(),
        };

        let canary = Canary {
            id: uuid::Uuid::new_v4().to_string(),
            canary_type,
            location: location.to_path_buf(),
            created_at: chrono::Utc::now().to_rfc3339(),
            description: format!("Balerx canary credential - {canary_type:?}"),
        };

        let old_entries = if force {
            let old: Vec<Canary> = self
                .canaries
                .iter()
                .filter(|(_, c)| paths_match(&c.location, location))
                .map(|(_, c)| c.clone())
                .collect();
            self.remove_registry_entries_for_path(location);
            old
        } else {
            Vec::new()
        };

        self.canaries.insert(canary.id.clone(), canary.clone());
        if let Err(e) = self.save_registry() {
            self.restore_registry_snapshot(&canary.id, old_entries);
            return Err(e).context(format!(
                "Failed to save canary registry after planting at: {}",
                location.display()
            ));
        }

        let mut options = fs::OpenOptions::new();
        options.write(true);
        if force {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }

        let mut file = match options.open(location) {
            Ok(file) => file,
            Err(e) => {
                return Err(self.failed_plant_error(
                    e,
                    &canary.id,
                    old_entries,
                    None,
                    format!(
                        "Failed to create canary file (registry rolled back): {}",
                        location.display()
                    ),
                ));
            }
        };

        if let Err(e) = write_canary_bytes(&mut file, content.as_bytes()) {
            drop(file);
            let created_by_this_call = !existed_before;
            return Err(self.failed_plant_error(
                e,
                &canary.id,
                old_entries,
                created_by_this_call.then_some(location),
                format!(
                    "Failed to write content to canary file (registry and file rolled back): {}",
                    location.display()
                ),
            ));
        }

        println!(
            "Planted {} canary at: {}",
            canary_type.name(),
            location.display()
        );
        println!("This is a FAKE credential for detection purposes only.");

        Ok(canary)
    }

    fn prepare_plant_location(location: &Path, force: bool) -> Result<bool> {
        Self::check_symlinks_in_path(location)?;

        let existed_before = match fs::symlink_metadata(location) {
            Ok(meta) if meta.is_symlink() => {
                anyhow::bail!(
                    "Target is a symbolic link and will not be overwritten: {}",
                    location.display()
                );
            }
            Ok(_) if !force => {
                anyhow::bail!(
                    "File already exists: {}. Use --force to overwrite.",
                    location.display()
                );
            }
            Ok(_) => true,
            Err(_) => false,
        };

        if let Some(parent) = location.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create parent directory for canary file: {}",
                    parent.display()
                )
            })?;
        }

        Ok(existed_before)
    }

    fn restore_registry_snapshot(&mut self, new_id: &str, old_entries: Vec<Canary>) {
        self.canaries.remove(new_id);
        for old_canary in old_entries {
            self.canaries.insert(old_canary.id.clone(), old_canary);
        }
    }

    fn rollback_failed_plant(
        &mut self,
        new_id: &str,
        old_entries: Vec<Canary>,
        remove_created: Option<&Path>,
    ) -> Result<()> {
        if let Some(path) = remove_created {
            let _ = fs::remove_file(path);
        }
        self.restore_registry_snapshot(new_id, old_entries);
        self.save_registry()
            .context("Failed to roll back canary registry after a plant failure")
    }

    fn failed_plant_error(
        &mut self,
        source: impl Into<anyhow::Error>,
        new_id: &str,
        old_entries: Vec<Canary>,
        remove_created: Option<&Path>,
        context: String,
    ) -> anyhow::Error {
        let error = source.into().context(context);
        match self.rollback_failed_plant(new_id, old_entries, remove_created) {
            Ok(()) => error,
            Err(rollback) => error.context(rollback),
        }
    }

    fn check_symlinks_in_path(path: &Path) -> Result<()> {
        for ancestor in path.ancestors().skip(1) {
            if skip_ancestor_symlink_check(ancestor) {
                continue;
            }
            if let Ok(meta) = fs::symlink_metadata(ancestor) {
                if meta.is_symlink() {
                    anyhow::bail!(
                        "Parent directory is a symbolic link and cannot be used: {}",
                        ancestor.display()
                    );
                }
            }
        }
        Ok(())
    }

    fn remove_registry_entries_for_path(&mut self, path: &Path) {
        let ids_to_remove: Vec<String> = self
            .canaries
            .iter()
            .filter(|(_, canary)| paths_match(&canary.location, path))
            .map(|(id, _)| id.clone())
            .collect();

        for id in ids_to_remove {
            self.canaries.remove(&id);
        }
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
        let mut canaries: Vec<&Canary> = self.canaries.values().collect();
        canaries.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        canaries
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DataOs {
    Windows,
    Macos,
    Linux,
}

#[derive(Clone, Copy)]
pub(crate) struct DataRootInput<'a> {
    pub balerx_data_dir: Option<&'a std::ffi::OsStr>,
    pub local_app_data: Option<&'a std::ffi::OsStr>,
    pub xdg_data_home: Option<&'a std::ffi::OsStr>,
    pub home: Option<&'a Path>,
    pub os: DataOs,
}

/// Data directory used by the activity log and the canary registry.
///
/// `BALERX_DATA_DIR` wins. Otherwise the directory is the platform data folder
/// joined with `balerx`, and that folder's home is [`crate::agent::home_dir`].
pub(crate) fn data_root() -> PathBuf {
    let balerx_data_dir = std::env::var_os("BALERX_DATA_DIR");
    let local_app_data = std::env::var_os("LOCALAPPDATA");
    let xdg_data_home = std::env::var_os("XDG_DATA_HOME");
    let home = crate::agent::home_dir();
    data_root_from(&DataRootInput {
        balerx_data_dir: balerx_data_dir.as_deref(),
        local_app_data: local_app_data.as_deref(),
        xdg_data_home: xdg_data_home.as_deref(),
        home: home.as_deref(),
        os: current_data_os(),
    })
}

pub(crate) fn current_data_os() -> DataOs {
    if cfg!(windows) {
        DataOs::Windows
    } else if cfg!(target_os = "macos") {
        DataOs::Macos
    } else {
        DataOs::Linux
    }
}

pub(crate) fn data_root_from(input: &DataRootInput<'_>) -> PathBuf {
    if let Some(dir) = nonempty(input.balerx_data_dir) {
        return PathBuf::from(dir);
    }
    if let Some(base) = platform_data_base(input) {
        return base.join("balerx");
    }
    PathBuf::from(".").join("balerx")
}

fn nonempty(value: Option<&std::ffi::OsStr>) -> Option<&std::ffi::OsStr> {
    value.filter(|value| !value.is_empty())
}

fn platform_data_base(input: &DataRootInput<'_>) -> Option<PathBuf> {
    match input.os {
        DataOs::Windows => {
            if let Some(local) = nonempty(input.local_app_data) {
                return Some(PathBuf::from(local));
            }
            input.home.map(|home| home.join("AppData").join("Local"))
        }
        DataOs::Macos => input
            .home
            .map(|home| home.join("Library").join("Application Support")),
        DataOs::Linux => {
            if let Some(xdg) = nonempty(input.xdg_data_home) {
                return Some(PathBuf::from(xdg));
            }
            input.home.map(|home| home.join(".local").join("share"))
        }
    }
}

fn write_canary_bytes(file: &mut fs::File, content: &[u8]) -> std::io::Result<()> {
    #[cfg(test)]
    if FORCE_WRITE_ERR.with(Cell::get) {
        return Err(std::io::Error::other("injected write failure"));
    }
    file.write_all(content)?;
    file.flush()?;
    Ok(())
}

fn skip_ancestor_symlink_check(path: &Path) -> bool {
    if path.as_os_str().is_empty() {
        return true;
    }
    let has_normal = path
        .components()
        .any(|component| matches!(component, Component::Normal(_)));
    if !has_normal {
        return true;
    }
    // macOS FIRLinks (`/tmp` → `/private/tmp`, `/var` → `/private/var`).
    // Refusing these would block every plant under the system temp directory.
    matches!(path.to_str(), Some("/tmp" | "/var" | "/etc" | "/private"))
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
    #[cfg(unix)]
    use std::sync::{Mutex, MutexGuard};

    #[cfg(unix)]
    static CWD_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(unix)]
    struct CwdGuard {
        prev: PathBuf,
        _lock: MutexGuard<'static, ()>,
    }

    #[cfg(unix)]
    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.prev);
        }
    }

    #[cfg(unix)]
    fn lock_cwd() -> CwdGuard {
        let lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        CwdGuard {
            prev: std::env::current_dir().expect("current directory"),
            _lock: lock,
        }
    }

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
    fn test_planted_files_contain_no_fake_banner() {
        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().join("registry.json");
        let mut manager = CanaryManager {
            registry_path,
            canaries: HashMap::new(),
        };

        for (canary_type, name) in [
            (CanaryType::AwsCredentials, "credentials"),
            (CanaryType::EnvFile, ".env"),
            (CanaryType::SshKey, "id_rsa"),
            (CanaryType::GenericSecret, "secret.txt"),
        ] {
            let path = temp_dir.path().join(name);
            manager.plant(canary_type, &path, false).unwrap();
            let content = fs::read_to_string(&path).unwrap();
            let upper = content.to_ascii_uppercase();
            assert!(!upper.contains("CANARY"), "{name} contained CANARY");
            assert!(!upper.contains("FAKE"), "{name} contained FAKE");
            assert!(
                !content.contains("Balerx Gate"),
                "{name} announced Balerx Gate"
            );
        }
    }

    #[test]
    fn test_canary_manager_plant_new_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().join("registry.json");

        let mut manager = CanaryManager {
            registry_path: registry_path.clone(),
            canaries: HashMap::new(),
        };

        let canary_path = temp_dir.path().join("test.env");
        let canary = manager
            .plant(CanaryType::EnvFile, &canary_path, false)
            .unwrap();

        assert_eq!(canary.canary_type, CanaryType::EnvFile);
        assert!(canary_path.exists());

        let reloaded = CanaryManager::new_from_path(&registry_path).unwrap();
        assert!(reloaded.is_canary(&canary_path).is_some());
        assert_eq!(reloaded.canaries.len(), 1);

        let content = fs::read_to_string(&canary_path).unwrap();
        assert!(!content.to_ascii_uppercase().contains("CANARY"));
        assert!(!content.to_ascii_uppercase().contains("FAKE"));
        assert!(!content.contains("Balerx Gate"));
    }

    #[test]
    fn test_canary_plant_existing_file_refused() {
        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().join("registry.json");

        let mut manager = CanaryManager {
            registry_path,
            canaries: HashMap::new(),
        };

        let canary_path = temp_dir.path().join("existing.env");
        fs::write(&canary_path, "existing content").unwrap();

        let result = manager.plant(CanaryType::EnvFile, &canary_path, false);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("File already exists"));

        let content = fs::read_to_string(&canary_path).unwrap();
        assert_eq!(content, "existing content");
    }

    #[test]
    fn test_canary_plant_force_overwrites() {
        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().join("registry.json");

        let mut manager = CanaryManager {
            registry_path: registry_path.clone(),
            canaries: HashMap::new(),
        };

        let canary_path = temp_dir.path().join("test.env");
        fs::write(&canary_path, "old content").unwrap();

        let canary = manager
            .plant(CanaryType::EnvFile, &canary_path, true)
            .unwrap();

        assert_eq!(canary.canary_type, CanaryType::EnvFile);
        assert!(canary_path.exists());

        let content = fs::read_to_string(&canary_path).unwrap();
        assert!(content.contains("DATABASE_URL"));
        assert!(!content.contains("old content"));

        let reloaded = CanaryManager::new_from_path(&registry_path).unwrap();
        assert_eq!(reloaded.canaries.len(), 1);
    }

    #[test]
    #[cfg(unix)]
    fn test_canary_plant_symlink_refused() {
        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().join("registry.json");

        let mut manager = CanaryManager {
            registry_path,
            canaries: HashMap::new(),
        };

        let target_path = temp_dir.path().join("target.env");
        fs::write(&target_path, "target content").unwrap();

        let symlink_path = temp_dir.path().join("link.env");
        std::os::unix::fs::symlink(&target_path, &symlink_path).unwrap();

        let result = manager.plant(CanaryType::EnvFile, &symlink_path, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symbolic link"));

        let result_force = manager.plant(CanaryType::EnvFile, &symlink_path, true);
        assert!(result_force.is_err());
        assert!(result_force
            .unwrap_err()
            .to_string()
            .contains("symbolic link"));

        let target_content = fs::read_to_string(&target_path).unwrap();
        assert_eq!(target_content, "target content");
    }

    #[test]
    #[cfg(unix)]
    fn test_canary_plant_dangling_symlink_refused() {
        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().join("registry.json");

        let mut manager = CanaryManager {
            registry_path,
            canaries: HashMap::new(),
        };

        let nonexistent = temp_dir.path().join("nonexistent");
        let symlink_path = temp_dir.path().join("dangling.env");

        std::os::unix::fs::symlink(&nonexistent, &symlink_path).unwrap();

        let result = manager.plant(CanaryType::EnvFile, &symlink_path, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symbolic link"));

        let result_force = manager.plant(CanaryType::EnvFile, &symlink_path, true);
        assert!(result_force.is_err());
        assert!(result_force
            .unwrap_err()
            .to_string()
            .contains("symbolic link"));
    }

    #[test]
    fn test_canary_plant_force_twice_single_registry_entry() {
        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().join("registry.json");

        let mut manager = CanaryManager {
            registry_path: registry_path.clone(),
            canaries: HashMap::new(),
        };

        let canary_path = temp_dir.path().join("test.env");

        let canary1 = manager
            .plant(CanaryType::EnvFile, &canary_path, false)
            .unwrap();

        let reloaded1 = CanaryManager::new_from_path(&registry_path).unwrap();
        assert_eq!(reloaded1.canaries.len(), 1);

        let canary2 = manager
            .plant(CanaryType::EnvFile, &canary_path, true)
            .unwrap();
        assert_ne!(canary1.id, canary2.id);

        let reloaded2 = CanaryManager::new_from_path(&registry_path).unwrap();
        assert_eq!(reloaded2.canaries.len(), 1);

        let entries_for_path: Vec<_> = reloaded2
            .canaries
            .values()
            .filter(|c| c.location == canary_path)
            .collect();
        assert_eq!(entries_for_path.len(), 1);
    }

    #[test]
    #[cfg(unix)]
    fn test_canary_plant_rollback_on_open_failure() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().join("registry.json");

        let mut manager = CanaryManager {
            registry_path: registry_path.clone(),
            canaries: HashMap::new(),
        };

        let readonly_dir = temp_dir.path().join("readonly");
        fs::create_dir(&readonly_dir).unwrap();

        let mut perms = fs::metadata(&readonly_dir).unwrap().permissions();
        perms.set_mode(0o444);
        if fs::set_permissions(&readonly_dir, perms.clone()).is_err() {
            eprintln!("Skipping test: cannot set read-only permissions (may be running as root)");
            return;
        }

        let test_file = readonly_dir.join("test-check.txt");
        if fs::write(&test_file, "test").is_ok() {
            eprintln!("Skipping test: read-only directory is still writable (running as root)");
            perms.set_mode(0o755);
            fs::set_permissions(&readonly_dir, perms).ok();
            return;
        }

        let canary_path = readonly_dir.join("test.env");
        let result = manager.plant(CanaryType::EnvFile, &canary_path, false);

        assert!(result.is_err());

        let reloaded = CanaryManager::new_from_path(&registry_path).unwrap();
        assert_eq!(reloaded.canaries.len(), 0);

        perms.set_mode(0o755);
        fs::set_permissions(&readonly_dir, perms).unwrap();
    }

    #[test]
    fn test_canary_list_is_sorted() {
        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().join("registry.json");

        let mut manager = CanaryManager {
            registry_path,
            canaries: HashMap::new(),
        };

        manager
            .plant(CanaryType::EnvFile, temp_dir.path().join("1.env"), false)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));

        manager
            .plant(
                CanaryType::AwsCredentials,
                temp_dir.path().join("2.aws"),
                false,
            )
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));

        manager
            .plant(CanaryType::SshKey, temp_dir.path().join("3.ssh"), false)
            .unwrap();

        let list = manager.list();
        assert_eq!(list.len(), 3);

        for i in 1..list.len() {
            assert!(list[i - 1].created_at <= list[i].created_at);
        }
    }

    #[test]
    fn test_canary_plant_force_rollback_preserves_old_entry() {
        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().join("registry.json");

        let mut manager = CanaryManager {
            registry_path: registry_path.clone(),
            canaries: HashMap::new(),
        };

        let canary_path = temp_dir.path().join("test.env");
        let canary1 = manager
            .plant(CanaryType::EnvFile, &canary_path, false)
            .unwrap();

        fs::remove_file(&canary_path).unwrap();
        fs::create_dir(&canary_path).unwrap();

        let result = manager.plant(CanaryType::EnvFile, &canary_path, true);
        assert!(result.is_err());

        let reloaded = CanaryManager::new_from_path(&registry_path).unwrap();
        assert_eq!(reloaded.canaries.len(), 1);
        assert!(reloaded.canaries.contains_key(&canary1.id));
        assert!(reloaded.is_canary(&canary_path).is_some());
    }

    #[test]
    fn test_canary_plant_rollback_on_write_failure() {
        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().join("registry.json");

        let mut manager = CanaryManager {
            registry_path: registry_path.clone(),
            canaries: HashMap::new(),
        };

        let canary_path = temp_dir.path().join("test.env");
        FORCE_WRITE_ERR.with(|flag| flag.set(true));
        let result = manager.plant(CanaryType::EnvFile, &canary_path, false);
        FORCE_WRITE_ERR.with(|flag| flag.set(false));

        assert!(result.is_err());
        assert!(!canary_path.exists());

        let reloaded = CanaryManager::new_from_path(&registry_path).unwrap();
        assert_eq!(reloaded.canaries.len(), 0);
    }

    #[test]
    fn test_canary_plant_force_write_failure_keeps_old_entry() {
        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().join("registry.json");

        let mut manager = CanaryManager {
            registry_path: registry_path.clone(),
            canaries: HashMap::new(),
        };

        let canary_path = temp_dir.path().join("test.env");
        let canary1 = manager
            .plant(CanaryType::EnvFile, &canary_path, false)
            .unwrap();

        FORCE_WRITE_ERR.with(|flag| flag.set(true));
        let result = manager.plant(CanaryType::EnvFile, &canary_path, true);
        FORCE_WRITE_ERR.with(|flag| flag.set(false));

        assert!(result.is_err());
        assert!(canary_path.exists());

        let reloaded = CanaryManager::new_from_path(&registry_path).unwrap();
        assert_eq!(reloaded.canaries.len(), 1);
        assert!(reloaded.canaries.contains_key(&canary1.id));
    }

    #[test]
    #[cfg(unix)]
    fn test_canary_plant_ancestor_symlink_refused() {
        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().join("registry.json");

        let mut manager = CanaryManager {
            registry_path,
            canaries: HashMap::new(),
        };

        let real_dir = temp_dir.path().join("real");
        fs::create_dir(&real_dir).unwrap();

        let symlink_dir = temp_dir.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

        let subdir = symlink_dir.join("sub");
        fs::create_dir_all(&subdir).unwrap();

        let canary_path = subdir.join("test.env");

        let result = manager.plant(CanaryType::EnvFile, &canary_path, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symbolic link"));

        assert!(!canary_path.exists());
    }

    #[test]
    fn skip_does_not_ignore_a_single_normal_component() {
        assert!(!skip_ancestor_symlink_check(Path::new("lp")));
        assert!(skip_ancestor_symlink_check(Path::new("")));
        assert!(skip_ancestor_symlink_check(Path::new("/")));
        assert!(skip_ancestor_symlink_check(Path::new("/tmp")));
    }

    #[test]
    #[cfg(unix)]
    fn test_canary_plant_relative_first_component_symlink_refused() {
        let _cwd = lock_cwd();
        let temp_dir = tempfile::tempdir().unwrap();
        std::env::set_current_dir(temp_dir.path()).unwrap();

        let registry_path = temp_dir.path().join("registry.json");
        let mut manager = CanaryManager {
            registry_path,
            canaries: HashMap::new(),
        };

        fs::create_dir("real").unwrap();
        std::os::unix::fs::symlink("real", "lp").unwrap();

        let result = manager.plant(CanaryType::EnvFile, "lp/y.env", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symbolic link"));

        let result_force = manager.plant(CanaryType::EnvFile, "lp/y.env", true);
        assert!(result_force.is_err());
        assert!(result_force
            .unwrap_err()
            .to_string()
            .contains("symbolic link"));

        assert!(!Path::new("real/y.env").exists());
        assert!(!Path::new("lp/y.env").exists());
    }

    #[test]
    fn data_root_uses_the_same_home_and_keeps_overrides() {
        let home = PathBuf::from("/profile");
        let linux = DataRootInput {
            balerx_data_dir: None,
            local_app_data: None,
            xdg_data_home: None,
            home: Some(&home),
            os: DataOs::Linux,
        };
        assert_eq!(
            data_root_from(&linux),
            PathBuf::from("/profile/.local/share/balerx")
        );
        let custom = DataRootInput {
            balerx_data_dir: Some(std::ffi::OsStr::new("/home/ada/Documents")),
            ..linux
        };
        assert_eq!(
            data_root_from(&custom),
            PathBuf::from("/home/ada/Documents")
        );
        let xdg = DataRootInput {
            xdg_data_home: Some(std::ffi::OsStr::new("/xdg")),
            balerx_data_dir: None,
            ..linux
        };
        assert_eq!(data_root_from(&xdg), PathBuf::from("/xdg/balerx"));
        let windows = DataRootInput {
            balerx_data_dir: None,
            local_app_data: Some(std::ffi::OsStr::new(r"C:\Users\Ada\AppData\Local")),
            xdg_data_home: None,
            home: Some(&home),
            os: DataOs::Windows,
        };
        assert_eq!(
            data_root_from(&windows),
            PathBuf::from(r"C:\Users\Ada\AppData\Local").join("balerx")
        );
        let macos = DataRootInput {
            os: DataOs::Macos,
            local_app_data: None,
            ..linux
        };
        assert_eq!(
            data_root_from(&macos),
            PathBuf::from("/profile/Library/Application Support/balerx")
        );
        let missing = DataRootInput {
            home: None,
            ..linux
        };
        assert_eq!(data_root_from(&missing), PathBuf::from("./balerx"));
    }
}
