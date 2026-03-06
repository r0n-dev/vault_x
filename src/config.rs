use crate::errors::VaultError;
use colored::*;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use rust_i18n::t;
use crate::cli;

pub const KEY_SIZE: usize = 32;
pub const SALT_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;
pub const ARGON2_M_COST: u32 = 19 * 1024;
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 1;
pub const CLIPBOARD_TIMEOUT_SECONDS: u64 = 30;
pub const AUTO_LOCK_TIMEOUT_MINUTES: u64 = 15;
pub const VAULT_FILE: &str = "vault_data.bin";
pub const CONFIG_FILE: &str = "vault_config.json";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultConfig {
    pub salt_hex: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub kdf_algorithm: String,
    pub keyfile_path: Option<String>,
    pub language: Option<String>,
    pub password_generator_symbols: Option<String>,
    #[serde(default)]
    pub defender_settings: DefenderSettings,
    #[serde(default = "default_auto_lock_timeout_config")]
    pub auto_lock_timeout_minutes: Option<u64>,
}

fn default_auto_lock_timeout_config() -> Option<u64> {
    Some(AUTO_LOCK_TIMEOUT_MINUTES)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HoneypotFileConfig {
    pub path: String,
    pub content_on_creation: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DefenderSettings {
    #[serde(default)]
    pub enable_behavioral_logging: bool,

    pub enable_realtime_file_monitoring: bool,
    pub debug_detection_level: String,
    pub enable_advanced_antidebug: bool,
    pub enable_vm_detection: bool,
    pub vm_detection_level: String,
    pub honeypot_files: Vec<HoneypotFileConfig>,
    pub enable_suspicious_process_scan: bool,
    pub suspicious_process_names: Vec<String>,
    pub suspicious_process_scan_level: String,

    pub enable_self_integrity_check: bool,
    pub integrity_check_level: String,

    #[serde(default = "default_false")]
    pub enable_executable_hash_check: bool,
    pub expected_executable_hash_sha256: Option<String>,
    #[serde(default = "default_integrity_action_level")]
    pub executable_hash_check_level: String,

    #[serde(default = "default_false")]
    pub enable_runtime_memory_integrity_check: bool,
    #[serde(default = "default_integrity_action_level")]
    pub runtime_memory_integrity_check_level: String,

    #[serde(default = "default_periodic_check_interval")]
    pub periodic_check_interval_seconds: Option<u64>,
    #[serde(default)]
    pub enable_win_peb_checks: bool,
    #[serde(default)]
    pub enable_win_ntqueryinfo_check: bool,
    #[serde(default)]
    pub enable_win_outputdebugstring_check: bool,
    #[serde(default)]
    pub enable_linux_ptrace_check: bool,
    #[serde(default)]
    pub enable_code_section_integrity_check: bool,
    #[serde(default)]
    pub enable_unusual_memory_region_check: bool,
}

fn default_false() -> bool { false }
fn default_integrity_action_level() -> String { "warn_user_critical".to_string() }


impl Default for DefenderSettings {
    fn default() -> Self {
        DefenderSettings {
            enable_behavioral_logging: false,
            enable_realtime_file_monitoring: true,
            debug_detection_level: "log_only".to_string(),
            enable_advanced_antidebug: false,
            enable_vm_detection: false,
            vm_detection_level: "log_only".to_string(),
            honeypot_files: vec![
                HoneypotFileConfig {
                    path: ".vault_x_decoy.log".to_string(),
                    content_on_creation: Some("This is a decoy log file. Access is monitored.".to_string()),
                },
            ],
            enable_suspicious_process_scan: false,
            suspicious_process_names: vec![
                "ollydbg".to_string(), "ida".to_string(), "ghidra".to_string(),
                "x64dbg".to_string(), "cheatengine".to_string(), "reclass".to_string(),
                "radare2".to_string(), "gdb".to_string(), "lldb".to_string(),
                "procmon".to_string(), "procexp".to_string(),
            ],
            suspicious_process_scan_level: "log_only".to_string(),
            enable_self_integrity_check: false,
            integrity_check_level: "warn_user_critical".to_string(),
            enable_executable_hash_check: false,
            expected_executable_hash_sha256: None,
            executable_hash_check_level: "warn_user_critical".to_string(),
            enable_runtime_memory_integrity_check: false,
            runtime_memory_integrity_check_level: "warn_user_critical".to_string(),
            periodic_check_interval_seconds: Some(30),
            enable_win_peb_checks: false,
            enable_win_ntqueryinfo_check: false,
            enable_win_outputdebugstring_check: false,
            enable_linux_ptrace_check: false,
            enable_code_section_integrity_check: false,
            enable_unusual_memory_region_check: false,
        }
    }
}

fn default_periodic_check_interval() -> Option<u64> {
    Some(30)
}

pub fn load_config() -> Result<VaultConfig, VaultError> {
    log::debug!("Versuche Konfigurationsdatei '{}' zu laden.", CONFIG_FILE);
    let config_path = PathBuf::from(CONFIG_FILE);
    if !config_path.exists() {
        log::warn!("Konfigurationsdatei '{}' nicht gefunden.", CONFIG_FILE);
        return Err(VaultError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Konfigurationsdatei '{}' nicht gefunden", CONFIG_FILE),
        )));
    }

    check_config_permissions(&config_path);

    let config_content = fs::read_to_string(&config_path)?;
    log::trace!("Konfigurationsdatei Inhalt: {}", config_content);

    match serde_json::from_str::<VaultConfig>(&config_content) {
        Ok(mut config) => {
            log::info!(
                "Konfiguration geladen. KDF: {}, Argon2(m={}, t={}, p={}), Keyfile: {:?}, Sprache: {:?}, Autolock: {:?} Min.",
                config.kdf_algorithm, config.m_cost, config.t_cost, config.p_cost,
                config.keyfile_path.is_some(),
                config.language,
                config.auto_lock_timeout_minutes.unwrap_or(AUTO_LOCK_TIMEOUT_MINUTES)
            );

            if config.auto_lock_timeout_minutes.is_none() {
                config.auto_lock_timeout_minutes = Some(AUTO_LOCK_TIMEOUT_MINUTES);
            }

            if config.kdf_algorithm != "Argon2id" {
                log::error!("Inkompatibler KDF Algorithmus gefunden: {}", config.kdf_algorithm);
                Err(VaultError::ConfigError(t!(
                    "errors.config_incompatible_kdf",
                    path = CONFIG_FILE,
                    algo = config.kdf_algorithm,
                    expected = "Argon2id",
                    vault_file = VAULT_FILE
                )))
            } else if config.m_cost == 0 || config.t_cost == 0 || config.p_cost == 0 {
                log::error!("Ungültige Argon2 Parameter (null) in Config gefunden.");
                Err(VaultError::ConfigError(t!(
                    "errors.config_invalid_argon_params",
                    path = CONFIG_FILE,
                    vault_file = VAULT_FILE
                )))
            }
            else if config.m_cost != ARGON2_M_COST || config.t_cost != ARGON2_T_COST || config.p_cost != ARGON2_P_COST {
                log::warn!(
                    "Argon2 Parameter in '{}' weichen von den Standardwerten (m={}, t={}, p={}) ab. Aktuell: m={}, t={}, p={}. Dies ist normal, wenn die Standards geändert wurden.",
                    CONFIG_FILE, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, config.m_cost, config.t_cost, config.p_cost
                );
                Ok(config)
            }
            else {
                Ok(config)
            }
        }
        Err(e) => {
            log::error!("Fehler beim Deserialisieren der Konfiguration: {}", e);
            Err(VaultError::Deserialization(e))
        }
    }
}

pub fn save_config(config: &VaultConfig) -> Result<(), VaultError> {
    log::debug!("Speichere Konfiguration nach '{}'.", CONFIG_FILE);
    let config_path = PathBuf::from(CONFIG_FILE);
    let config_content = serde_json::to_string_pretty(config)?;

    let temp_path = format!("{}.tmp", config_path.display());
    {
        let mut file = fs::File::create(&temp_path)?;
        #[cfg(unix)]
        {
            if let Ok(metadata) = file.metadata() {
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o600);
                if let Err(e) = fs::set_permissions(&temp_path, permissions) {
                    log::warn!("Konnte Berechtigungen für temporäre Config-Datei '{}' nicht setzen: {}", temp_path, e);
                }
            }
        }
        file.write_all(config_content.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&temp_path, &config_path)?;

    check_config_permissions(&config_path);

    log::info!("Konfiguration erfolgreich gespeichert.");
    Ok(())
}

pub fn initialize_new_config(config_path_param: &Path) -> Result<VaultConfig, VaultError> {
    log::info!("Erstelle neue Vault-Konfiguration für Pfad: {}", config_path_param.display());
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    log::debug!("Neuen Salt generiert.");

    let keyfile_string_path = match cli::prompt_for_keyfile_setup() {
        Ok(path_opt) => path_opt,
        Err(e) => {
            log::error!("Kritischer Fehler während des Keyfile-Setup-Dialogs: {}", e);
            return Err(e);
        }
    };

    let available_langs_vec: Vec<&str> = rust_i18n::available_locales!().to_vec();
    let mut language_str: Option<String> = None;
    let default_lang_code = "en";

    if available_langs_vec.is_empty() {
        log::warn!("Keine konfigurierbaren Sprachen gefunden. Fallback auf '{}'.", default_lang_code);
        language_str = Some(default_lang_code.to_string());
    } else {
        println!("\n{}", "----------------------------------------".dimmed());
        println!(
            "{}",
            format!(
                "{} / {}",
                t!("config.language_selection_title", locale = "en"),
                t!("config.language_selection_title", locale = "de")
            )
            .bold()
            .cyan()
        );

        for (idx, lang_code) in available_langs_vec.iter().enumerate() {
            let display_name = match *lang_code {
                "de" => t!("config.language_name_de"),
                "en" => t!("config.language_name_en"),
                "es" => t!("config.language_name_es"),
                "fr" => t!("config.language_name_fr"),
                "it" => t!("config.language_name_it"),
                "pt" => t!("config.language_name_pt"),
                "nl" => t!("config.language_name_nl"),
                "pl" => t!("config.language_name_pl"),
                "tr" => t!("config.language_name_tr"),
                "ru" => t!("config.language_name_ru"),
                "ja" => t!("config.language_name_ja"),
                "zh-CN" => t!("config.language_name_zh-CN"),
                _ => lang_code.to_string(),
            };
            println!("  [{}] {}", (idx + 1).to_string().green(), display_name);
        }

        let default_display_name = match default_lang_code {
             "de" => t!("config.language_name_de"),
             "en" => t!("config.language_name_en"),
             "es" => t!("config.language_name_es"),
             "fr" => t!("config.language_name_fr"),
             "it" => t!("config.language_name_it"),
             "pt" => t!("config.language_name_pt"),
             "nl" => t!("config.language_name_nl"),
             "pl" => t!("config.language_name_pl"),
             "tr" => t!("config.language_name_tr"),
             "ru" => t!("config.language_name_ru"),
             "ja" => t!("config.language_name_ja"),
             "zh-CN" => t!("config.language_name_zh-CN"),
             _ => default_lang_code.to_string(),
        };
        let default_option_text = format!(
            "0: {} ({})",
            default_display_name,
            t!("common.default_option")
        );
        println!("  [{}]", default_option_text.yellow());
        println!("{}", "----------------------------------------".dimmed());

        loop {
            print!(
                "{} / {}: ",
                t!("config.prompt_select_language_number", locale = "en"),
                t!("config.prompt_select_language_number", locale = "de")
            );
            io::stdout().flush()?;
            let mut choice_input = String::new();
            io::stdin().read_line(&mut choice_input)?;
            let choice_trimmed = choice_input.trim();

            if choice_trimmed == "0" || choice_trimmed.is_empty() {
                language_str = Some(default_lang_code.to_string());
                println!("✅ {}", t!("config.info_language_selected_default", lang = default_lang_code, locale = default_lang_code));
                log::info!("Sprache auf Standard '{}' gesetzt.", default_lang_code);
                break;
            }

            match choice_trimmed.parse::<usize>() {
                Ok(num) if num > 0 && num <= available_langs_vec.len() => {
                    let selected_lang_code = available_langs_vec[num - 1];
                    language_str = Some(selected_lang_code.to_string());
                    println!("✅ {}", t!("config.info_language_selected", lang = selected_lang_code, locale = selected_lang_code));
                    log::info!("Sprache '{}' ausgewählt.", selected_lang_code);
                    break;
                }
                _ => {
                    println!(
                        "{} / {}",
                        t!("errors.invalid_number_choice", locale = "en", min = 1, max = available_langs_vec.len()).red(),
                        t!("errors.invalid_number_choice", locale = "de", min = 1, max = available_langs_vec.len()).red()
                    );
                }
            }
        }
    }
    rust_i18n::set_locale(language_str.as_deref().unwrap_or(default_lang_code));


    let new_config = VaultConfig {
        salt_hex: hex::encode(salt),
        m_cost: ARGON2_M_COST,
        t_cost: ARGON2_T_COST,
        p_cost: ARGON2_P_COST,
        kdf_algorithm: "Argon2id".to_string(),
        keyfile_path: keyfile_string_path,
        language: language_str,
        password_generator_symbols: Some(String::from_utf8_lossy(crate::crypto::DEFAULT_PASSWORD_SYMBOLS).into_owned()),
        defender_settings: DefenderSettings::default(),
        auto_lock_timeout_minutes: Some(AUTO_LOCK_TIMEOUT_MINUTES),
    };

    if let Err(e) = save_config(&new_config) {
        log::error!("Fehler beim Speichern der initialen Konfiguration: {}", e);
        return Err(e);
    }
    println!("✅ {}", t!("config.info_config_saved", file=CONFIG_FILE).green());
    Ok(new_config)
}


#[cfg(unix)]
fn check_permissions_unix(path: &Path, expected_mode: u32, warning_key: &str) {
    match fs::metadata(path) {
        Ok(metadata) => {
            let permissions = metadata.permissions();
            if (permissions.mode() & 0o777) != expected_mode {
                log::warn!(
                    "Unsichere Berechtigungen für '{}' (aktuell: {:o}, erwartet: {:o}).",
                    path.display(),
                    permissions.mode() & 0o777,
                    expected_mode
                );
                println!("{}", t!(warning_key, path = path.display()).yellow().bold());
            } else {
                log::debug!("Berechtigungen für '{}' sind korrekt ({:o}).", path.display(), expected_mode);
            }
        }
        Err(e) => {
            log::warn!("Konnte Metadaten für '{}' nicht lesen, um Berechtigungen zu prüfen: {}", path.display(), e);
        }
    }
}

pub fn check_config_permissions(path: &Path) {
    #[cfg(unix)]
    check_permissions_unix(path, 0o600, "warnings.insecure_config_permissions");

    #[cfg(windows)]
    {
        let _ = path;
        log::debug!("Berechtigungsprüfung für Konfigurationsdatei unter Windows ist derzeit nicht implementiert.");
    }
}

pub fn check_keyfile_permissions(path: &Path) {
    #[cfg(unix)]
    check_permissions_unix(path, 0o400, "warnings.insecure_keyfile_permissions");

    #[cfg(windows)]
    {
        let _ = path;
        log::debug!("Berechtigungsprüfung für Keyfile unter Windows ist derzeit nicht implementiert.");
    }
}