#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate rust_i18n;

use crate::config::{VaultConfig, AUTO_LOCK_TIMEOUT_MINUTES, VAULT_FILE, CONFIG_FILE};
use crate::errors::{VaultError, DefenderAlert, DefenderAlertReason, DefenderActionLevel};
use crate::models::{AppState};
use crate::defender_ai_logger::ExternalEvent;

use colored::*;
use std::io::{self, Write};
use std::path::PathBuf;
use std::thread::{sleep, spawn as spawn_thread};
use std::time::{Duration, Instant};
use zeroize::Zeroize;
use std::sync::{Arc, RwLock, Mutex, mpsc};
use notify::{Watcher as NotifyWatcherTrait, Event as NotifyEvent};


use flexi_logger::{FileSpec, Logger, WriteMode, Duplicate, Criterion, Naming, Cleanup};

rust_i18n::i18n!("locales", fallback = "en");

mod cli;
mod config;
mod crypto;
mod errors;
mod models;
mod vault_logic;
mod defender;
mod game;
mod defender_ai_logger;


const VERSION: &str = env!("CARGO_PKG_VERSION");

lazy_static! {
    static ref FILE_WATCHER_HOLDER: Mutex<Option<Box<dyn NotifyWatcherTrait + Send + Sync>>> = Mutex::new(None);
}


fn lock_app_state(app_state_arc: &Arc<RwLock<AppState>>) {
    match app_state_arc.write() {
        Ok(mut state) => {
            if !state.locked {
                state.locked = true;
                state.last_activity = Instant::now();
                if let Some(mut key) = state.key.take() {
                    key.zeroize();
                    log::info!("Vault wurde gesperrt und Schlüssel genullt.");
                } else {
                    log::info!("Vault wurde gesperrt (kein Schlüssel vorhanden oder bereits genullt).");
                }
            } else {
                log::debug!("Vault ist bereits gesperrt.");
            }
        }
        Err(e) => {
            log::error!("Kritischer Fehler: Konnte App-Zustand zum Sperren nicht schreiben (Poisoned Lock): {}", e);
            eprintln!("\n{}\n", t!("errors.critical_state_lock_failed").red().bold());
            std::process::exit(1);
        }
    }
}

fn is_vault_locked(app_state_arc: &Arc<RwLock<AppState>>) -> bool {
    match app_state_arc.read() {
        Ok(state) => state.locked || state.key.is_none(),
        Err(_) => {
            log::error!("Konnte App-Zustand zum Prüfen der Sperrung nicht lesen (read lock). Betrachte als gesperrt.");
            true
        }
    }
}

fn update_last_activity(app_state_arc: &Arc<RwLock<AppState>>) {
    if let Ok(mut state_write) = app_state_arc.write() {
        state_write.last_activity = Instant::now();
    }
}


fn main() -> Result<(), VaultError> {
    Logger::try_with_str("info, vault_x_cli=debug")
        .unwrap()
        .log_to_file(FileSpec::default().basename("vaultx_debug"))
        .write_mode(WriteMode::BufferAndFlush)
        .duplicate_to_stderr(Duplicate::Warn)
        .rotate(
            Criterion::Size(2 * 1024 * 1024),
            Naming::Timestamps,
            Cleanup::KeepCompressedFiles(5),
        )
        .start()
        .unwrap();

    rust_i18n::set_locale("de");
    log::info!("========================================================");
    log::info!("VaultX CLI Version {} gestartet.", VERSION);
    log::info!("Betriebssystem: {}", std::env::consts::OS);
    log::info!("Architektur: {}", std::env::consts::ARCH);

    let config_path = PathBuf::from(CONFIG_FILE);
    let vault_path = PathBuf::from(VAULT_FILE);
    let mut config_main: VaultConfig;
    let app_state_arc: Arc<RwLock<AppState>>;

    if !config_path.exists() {
        log::warn!("Keine Konfigurationsdatei gefunden. Erstelle neue Konfiguration und neuen Vault.");
        if vault_path.exists() {
            log::warn!("Vault-Datei '{}' gefunden, aber keine Konfigurationsdatei. Die alte Vault-Datei wird ignoriert/überschrieben.", vault_path.display());
        }
        cli::clear_screen()?;
        println!("{}", t!("cli.welcome_new").green().bold());
        println!("{}\n", t!("cli.first_setup_prompt"));
        let initial_config = match config::initialize_new_config(&config_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                log::error!("Fehler bei der Initialisierung der neuen Konfiguration: {}", e);
                eprintln!("{}\n", t!("errors.config_error", details = e.to_string()).red().bold());
                return Err(e);
            }
        };
        config_main = initial_config.clone();
        let initial_password = cli::prompt_new_master_password()?;
        cli::clear_screen()?;
        println!("{}", t!("cli.config_created_success").green());
        println!("{}", t!("cli.vault_init_prompt"));
        let new_app_state = match vault_logic::initialize_new_vault_from_config(initial_password, &config_main) {
            Ok(state) => state,
            Err(e) => {
                log::error!("Fehler bei der Initialisierung des neuen Vaults aus Config: {}", e);
                eprintln!("{}\n", t!("errors.new_vault_init_failed", details = e.to_string()).red().bold());
                return Err(e);
            }
        };
        app_state_arc = Arc::new(RwLock::new(new_app_state));
        match app_state_arc.read() {
            Ok(state_read) => {
                if let Some(key) = &state_read.key {
                    if let Err(e) = vault_logic::save_vault(&state_read.vault, key) {
                        log::error!("Fehler beim initialen Speichern des Vaults: {}", e);
                        eprintln!("{}\n", t!("errors.initial_vault_save_failed", details = e.to_string()).red().bold());
                        cli::wait_for_enter()?;
                    } else {
                        log::info!("Initialer leerer Vault in '{}' gespeichert.", VAULT_FILE);
                    }
                } else {
                    log::error!("Kritischer Fehler: Kein Schlüssel nach initialize_new_vault_from_config vorhanden.");
                    eprintln!("\n{}\n", t!("errors.critical_no_key_after_init").red().bold());
                    return Err(VaultError::ConfigError("Kein Schlüssel nach Initialisierung".to_string()));
                }
            }
            Err(_) => {
                log::error!("Kritischer Fehler: Konnte initialen App-Zustand nicht lesen (Poisoned Lock).");
                eprintln!("\n{}\n", t!("errors.critical_state_lock_failed").red().bold());
                return Err(VaultError::ConfigError("App State Lock vergiftet".to_string()));
            }
        }
    } else {
        config_main = match config::load_config() {
            Ok(cfg) => {
                log::info!("Konfiguration aus '{}' geladen.", CONFIG_FILE);
                cfg
            }
            Err(e) => {
                log::error!("Fehler beim Laden der Konfiguration: {}", e);
                eprintln!("{}\n", t!("errors.config_load_failed", details = e.to_string()).red().bold());
                eprintln!("{}", t!("errors.hint_delete_config_reinit", config_file = CONFIG_FILE).yellow());
                return Err(e);
            }
        };
        if let Some(lang) = &config_main.language {
            rust_i18n::set_locale(lang);
            log::info!("Sprache auf '{}' gesetzt gemäß Konfiguration.", lang);
        } else {
            rust_i18n::set_locale("en");
            log::info!("Keine Sprache in Konfiguration gefunden, Fallback auf 'en'.");
        }
        cli::clear_screen()?;
        println!("{}", t!("cli.welcome_back").green().bold());
        let entered_password = cli::prompt_single_password(&t!("prompts.enter_master_password"))?;
        let loaded_app_state = match vault_logic::unlock_and_load_vault(&config_main, entered_password) {
            Ok(state) => {
                log::info!("Vault erfolgreich geladen und entschlüsselt.");
                let mut state_unlocked = state;
                state_unlocked.locked = false;
                state_unlocked.last_activity = Instant::now();
                state_unlocked
            }
            Err(VaultError::PasswordOrKeyfileVerification) => {
                log::error!("{}", t!("log.master_password_or_keyfile_incorrect_on_load"));
                eprintln!("\n{}\n", t!("errors.master_password_or_keyfile_incorrect").red().bold());
                eprintln!("{}", t!("errors.hint_check_password_keyfile").yellow());
                 std::process::exit(1);
            }
            Err(e) => {
                log::error!("Fehler beim Laden oder Entschlüsseln des Vaults: {}", e);
                eprintln!("{}\n", t!("errors.vault_load_decrypt_failed", details = e.to_string()).red().bold());
                eprintln!("{}", t!("errors.hint_check_config", config_file = CONFIG_FILE, vault_file = VAULT_FILE).yellow());
                eprintln!("{}", t!("errors.hint_check_keyfile").yellow());
                eprintln!("{}", t!("errors.hint_check_permissions", vault_file = VAULT_FILE, config_file = CONFIG_FILE).yellow());
                return Err(e);
            }
        };
        app_state_arc = Arc::new(RwLock::new(loaded_app_state));
    }

    let (defender_tx, defender_rx) = mpsc::channel::<DefenderAlert>();
    let (ai_event_tx, ai_event_rx) = mpsc::channel::<ExternalEvent>();

    if config_main.defender_settings.enable_behavioral_logging {
        log::info!("Verhaltensbasiertes Logging (AI Overlord) ist aktiviert. Starte Analyse-Engine.");
        let ai_app_state = Arc::clone(&app_state_arc);
        let ai_settings = Arc::new(config_main.defender_settings.clone());
        let (shutdown_tx, _shutdown_rx) = mpsc::channel::<()>();
        let ai_alert_tx = defender_tx.clone();

        spawn_thread(move || {
            defender_ai_logger::run_ai_overlord(ai_app_state, shutdown_tx, ai_alert_tx, ai_settings, ai_event_rx);
        });
    } else {
        log::info!("Verhaltensbasiertes Logging (AI Overlord) ist deaktiviert.");
    }


    let defender_settings_clone = config_main.defender_settings.clone();
    let settings_arc_for_defender = Arc::new(defender_settings_clone);
    
    let watcher_event_handler = move |res: Result<NotifyEvent, notify::Error>| {
        if let Ok(event) = res {
            if let Some(path) = event.paths.first() {
                let access_type = match event.kind {
                    notify::EventKind::Access(_) => "Read".to_string(),
                    notify::EventKind::Create(_) => "Create".to_string(),
                    notify::EventKind::Modify(_) => "Write".to_string(),
                    notify::EventKind::Remove(_) => "Delete".to_string(),
                     _ => "Unknown".to_string(),
                };

                if let Err(e) = ai_event_tx.send(ExternalEvent::FileAccess { 
                    path: path.clone(), 
                    process_id: None,
                    access_type, 
                    details: None 
                }) {
                    log::trace!("Konnte Datei-Event nicht an AI Engine senden (vermutlich deaktiviert): {}", e);
                }
            }
        }
    };


    match defender::initialize_defender_massively(settings_arc_for_defender.clone(), defender_tx.clone()) {
        Ok(optional_watcher) => {
            if let Some(watcher_concrete) = optional_watcher {
                if let Ok(mut watcher_guard) = FILE_WATCHER_HOLDER.lock() {
                    *watcher_guard = Some(Box::new(watcher_concrete));
                }
            }
        }
        Err(e) => {
            log::error!("Fehler bei der Defender-Initialisierung: {}", e);
            eprintln!("\n{}\n", t!("errors.defender_init_failed", details = e.to_string()).red().bold());
            cli::wait_for_enter()?;
        }
    }


    let app_state_clone_for_defender_handler = Arc::clone(&app_state_arc);
    spawn_thread(move || {
        log::info!("Defender-Nachrichten-Handler-Thread gestartet.");
        for alert in defender_rx {
            log::warn!("Defender Alert empfangen: Reason: {:?}, Suggested Action: {:?}", alert.reason, alert.suggested_action_level);
            let mut perform_shutdown = false;
            let mut lock_vault_alert = false;
            let (banner, details) = match &alert.reason {
                 DefenderAlertReason::AiThreatEscalation { process_name, pid, score, detected_indicators } => (
                    format!("{} {}", "🚨".red(), t!("errors.defender_alert_banner_ai_threat").bold()),
                    format!("{}\n    PID: {}\n    {}\n\n    {}\n{}",
                        t!("errors.defender_alert_reason_ai_threat_process", name = process_name.yellow().bold()),
                        pid.to_string().yellow(),
                        t!("errors.defender_alert_reason_ai_threat_score", score = score.to_string().red().bold()),
                        t!("errors.defender_alert_reason_ai_threat_indicators_title").underline(),
                        detected_indicators.join("\n    - ").dimmed()
                    )
                ),
                DefenderAlertReason::CriticalFileModified(path, action) => (
                    t!("errors.defender_alert_banner_critical_file"),
                    t!("errors.defender_alert_detail_critical_file", path = path.display(), action = action)
                ),
                DefenderAlertReason::HoneypotTriggered(path, action_description) => (
                    t!("errors.defender_alert_banner_security"),
                    t!("errors.defender_alert_detail_honeypot", path = path.display(), action_description = action_description)
                ),
                DefenderAlertReason::DebuggerDetected(details_str) => (
                    t!("errors.defender_alert_prefix_security"),
                    t!("errors.defender_alert_reason_debugger_detected", details = details_str.yellow().bold())
                ),
                DefenderAlertReason::VMDetected(details_str) => (
                    t!("errors.defender_alert_prefix_security"),
                    t!("errors.defender_alert_reason_vm_detected", details = details_str.yellow().bold())
                ),
                DefenderAlertReason::SuspiciousProcessFound(summary, processes) => (
                    t!("errors.defender_alert_prefix_security"),
                    format!("{}{}",
                        t!("errors.defender_alert_reason_suspicious_process_summary", summary_text = summary.yellow().bold()),
                        if !processes.is_empty() { format!("\n{}", t!("errors.defender_alert_reason_suspicious_process_found_processes", processes_details = format!("{:?}", processes).dimmed())) } else { "".to_string() }
                    )
                ),
                DefenderAlertReason::ParentProcessSuspicious(current_proc, parent_info) => (
                    t!("errors.defender_alert_prefix_security"),
                    t!("errors.defender_alert_reason_parent_suspicious", current_proc = current_proc.yellow().bold(), parent_info = parent_info.yellow().bold())
                ),
                DefenderAlertReason::ExecutableHashMismatch { executable_path, expected_hash, calculated_hash } => (
                    format!("{} {}", t!("errors.defender_alert_prefix_integrity"), t!("errors.defender_alert_executable_hash_mismatch_title")),
                    format!("{}\n    {}\n    {}",
                        t!("errors.defender_alert_reason_executable_hash_mismatch_detail", path = executable_path.yellow().bold()),
                        t!("errors.defender_alert_reason_executable_hash_expected", hash = expected_hash.dimmed()),
                        t!("errors.defender_alert_reason_executable_hash_calculated", hash = calculated_hash.red().bold())
                    )
                ),
                DefenderAlertReason::RuntimeCriticalFunctionTampered { function_address, original_bytes_preview, current_bytes_preview } => (
                    format!("{} {}", t!("errors.defender_alert_prefix_memory"), t!("errors.defender_alert_runtime_tamper_title")),
                    format!("{}\n    {}\n    {}",
                        t!("errors.defender_alert_reason_runtime_tamper_detail", address = function_address.yellow().bold()),
                        t!("errors.defender_alert_reason_runtime_tamper_original", bytes = original_bytes_preview.dimmed()),
                        t!("errors.defender_alert_reason_runtime_tamper_current", bytes = current_bytes_preview.red().bold())
                    )
                ),
                DefenderAlertReason::SuspiciousEnvironmentVariable(summary, vars) => (
                    t!("errors.defender_alert_prefix_config"),
                    format!("{} ({})", summary.yellow().bold(), vars.dimmed())
                ),
                DefenderAlertReason::UnusualMemoryRegion(description) => (
                    t!("errors.defender_alert_prefix_memory"),
                    t!("errors.defender_alert_reason_unusual_mem_region", description = description.yellow().bold())
                ),
                DefenderAlertReason::LinuxPtraceAttached(errno) => (
                    t!("errors.defender_alert_prefix_security"),
                    t!("errors.defender_alert_reason_ptrace_attached", errno = errno)
                ),
                DefenderAlertReason::PebBeingDebuggedFlagDetected => (
                    t!("errors.defender_alert_prefix_security"),
                    t!("errors.defender_alert_reason_peb_debug_flag")
                ),
                DefenderAlertReason::NtGlobalFlagDebuggedDetected => (
                    t!("errors.defender_alert_prefix_security"),
                    t!("errors.defender_alert_reason_nt_global_flag")
                ),
            };
            eprintln!("\n\n{}\n{}\n\n{}",
                banner.red().bold(),
                details.red(),
                "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!".red().bold()
            );
            match alert.suggested_action_level {
                DefenderActionLevel::LogOnly => {}
                DefenderActionLevel::WarnUser => { eprintln!("{}", t!("errors.defender_recommend_caution").yellow()); }
                DefenderActionLevel::WarnUserCritical => { eprintln!("{}", t!("errors.defender_recommend_exit").red().bold()); }
                DefenderActionLevel::LockVault => { eprintln!("{}", t!("errors.defender_locking_vault").red().bold()); lock_vault_alert = true; }
                DefenderActionLevel::Shutdown => { eprintln!("{}", t!("errors.defender_forcing_exit_critical").red().bold()); lock_vault_alert = true; perform_shutdown = true; }
            }
            if lock_vault_alert {
                lock_app_state(&app_state_clone_for_defender_handler);
            }
            if perform_shutdown {
                eprintln!("{}", t!("cli.app.shutting_down_in_5_seconds").red().bold());
                sleep(Duration::from_secs(5));
                std::process::exit(1);
            }
        }
        log::info!("Defender-Nachrichten-Handler-Thread beendet.");
    });


    loop {
        let auto_lock_enabled = config_main.auto_lock_timeout_minutes.unwrap_or(0) > 0;
        if auto_lock_enabled && !is_vault_locked(&app_state_arc) {
            if let Ok(state_read) = app_state_arc.read() {
                let lock_timeout_minutes = config_main.auto_lock_timeout_minutes.unwrap_or(AUTO_LOCK_TIMEOUT_MINUTES);
                if lock_timeout_minutes > 0 {
                    let elapsed_inactive_time = state_read.last_activity.elapsed();
                    if elapsed_inactive_time > Duration::from_secs(lock_timeout_minutes * 60) {
                        drop(state_read);
                        lock_app_state(&app_state_arc);
                        cli::clear_screen()?;
                        println!("{}", t!("messages.vault_auto_locked").yellow().bold());
                        cli::wait_for_enter()?;
                        continue;
                    }
                }
            }
        }
        cli::clear_screen()?;
        println!("{}", t!("cli.app.title").green().bold());
        println!("{}\n", t!("cli.app.version", version = VERSION));

        cli::show_menu();

        print!("{} ", t!("menu.prompt").cyan());
        io::stdout().flush()?;
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        let choice = choice.trim();

        cli::clear_screen()?;

        if is_vault_locked(&app_state_arc) && !matches!(choice.to_uppercase().as_str(), "U" | "9" | "42" | "CHARLIE" | "CIPHER" | "BINARY" | "O" | "8") {
            println!("\n{}", t!("messages.vault_is_locked").yellow());
            cli::wait_for_enter()?;
            continue;
        }

        let mut vault_modified = false;
        let mut action_performed_requires_wait = true;

        match choice.to_uppercase().as_str() {
            "1" => {
                if !is_vault_locked(&app_state_arc) {
                    match app_state_arc.write() {
                        Ok(mut state) => {
                             let custom_symbols = config_main.password_generator_symbols.as_deref();
                             match cli::add_password_cli(&mut state.vault, custom_symbols) {
                                 Ok(added) => { if added { vault_modified = true; } }
                                 Err(e) => { eprintln!("{}\n", t!("errors.add_password_failed", details = e.to_string()).red().bold()); }
                             }
                        }
                        Err(_) => {
                           eprintln!("{}", t!("errors.vault_lock_write_failed", details = "Passwort hinzufügen").red().bold());
                        }
                    }
                     update_last_activity(&app_state_arc);
                } else { println!("{}", t!("messages.vault_is_locked").yellow()); }
            }
            "2" => {
                 cli::clear_screen()?;
                 match app_state_arc.read() {
                     Ok(state_read) => {
                         if !state_read.locked {
                              let filtered_indices = cli::show_passwords_cli(&state_read.vault)?;
                              cli::view_or_copy_password_cli(&state_read.vault, &filtered_indices)?;
                              update_last_activity(&app_state_arc);
                         } else { println!("{}", t!("messages.vault_is_locked").yellow()); }
                     }
                      Err(_) => {
                        eprintln!("{}", t!("errors.vault_lock_read_failed", details = "Eintragssuche").red().bold());
                      }
                 }
            }
            "3" => {
                cli::clear_screen()?;
                match app_state_arc.read() {
                    Ok(state_read) => {
                         if !state_read.locked {
                             let filtered_indices = cli::show_passwords_cli(&state_read.vault)?;
                             cli::view_or_copy_password_cli(&state_read.vault, &filtered_indices)?;
                             update_last_activity(&app_state_arc);
                         } else {
                             println!("{}", t!("messages.vault_is_locked").yellow());
                         }
                    }
                    Err(_) => {
                        eprintln!("{}", t!("errors.vault_lock_read_failed", details = "Passwortanzeige").red().bold());
                    }
                }
            }
            "4" => {
                 if !is_vault_locked(&app_state_arc) {
                     match app_state_arc.write() {
                         Ok(mut state) => {
                             match cli::delete_password_cli(&mut state.vault) {
                                 Ok(deleted) => { if deleted { vault_modified = true; } }
                                 Err(e) => { eprintln!("{}\n", t!("errors.delete_password_failed", details = e.to_string()).red().bold()); }
                             }
                         }
                         Err(_) => {
                           eprintln!("{}", t!("errors.vault_lock_write_failed", details = "Passwort löschen").red().bold());
                         }
                     }
                      update_last_activity(&app_state_arc);
                 } else { println!("{}", t!("messages.vault_is_locked").yellow()); }
            }
            "E" => {
                if !is_vault_locked(&app_state_arc) {
                    match app_state_arc.write() {
                        Ok(mut state) => {
                             let custom_symbols = config_main.password_generator_symbols.as_deref();
                             match cli::edit_password_cli(&mut state.vault, custom_symbols) {
                                 Ok(edited) => { if edited { vault_modified = true; } }
                                 Err(e) => { eprintln!("{}\n", t!("errors.edit_password_failed", details = e.to_string()).red().bold()); }
                             }
                        }
                        Err(_) => {
                            eprintln!("{}", t!("errors.vault_lock_write_failed", details = "Passwort bearbeiten").red().bold());
                        }
                    }
                     update_last_activity(&app_state_arc);
                } else { println!("{}", t!("messages.vault_is_locked").yellow()); }
            }
            "5" => {
                if !is_vault_locked(&app_state_arc) {
                    match app_state_arc.write() {
                        Ok(mut state) => {
                             match cli::add_note_cli(&mut state.vault) {
                                 Ok(added) => { if added { vault_modified = true; } }
                                 Err(e) => { eprintln!("{}\n", t!("errors.add_note_failed", details = e.to_string()).red().bold()); }
                             }
                        }
                         Err(_) => {
                            eprintln!("{}", t!("errors.vault_lock_write_failed", details = "Notiz hinzufügen").red().bold());
                         }
                    }
                     update_last_activity(&app_state_arc);
                } else { println!("{}", t!("messages.vault_is_locked").yellow()); }
            }
            "6" => {
                cli::clear_screen()?;
                 match app_state_arc.read() {
                     Ok(state) => {
                         if !state.locked {
                            cli::show_notes_cli(&state.vault)?;
                            update_last_activity(&app_state_arc);
                          }
                         else { println!("{}", t!("messages.vault_is_locked").yellow()); }
                     }
                     Err(_) => {
                        eprintln!("{}", t!("errors.vault_lock_read_failed", details = "Notizen anzeigen").red().bold());
                     }
                 }
            }
            "7" => {
                  if !is_vault_locked(&app_state_arc) {
                      match app_state_arc.write() {
                          Ok(mut state) => {
                              match cli::delete_note_cli(&mut state.vault) {
                                  Ok(deleted) => { if deleted { vault_modified = true; } }
                                  Err(e) => { eprintln!("{}\n", t!("errors.delete_note_failed", details = e.to_string()).red().bold()); }
                              }
                          }
                          Err(_) => {
                            eprintln!("{}", t!("errors.vault_lock_write_failed", details = "Notiz löschen").red().bold());
                          }
                      }
                       update_last_activity(&app_state_arc);
                  } else { println!("{}", t!("messages.vault_is_locked").yellow()); }
             }
            "K" => {
                  if !is_vault_locked(&app_state_arc) {
                      match app_state_arc.write() {
                          Ok(mut state) => {
                              match cli::edit_note_cli(&mut state.vault) {
                                  Ok(edited) => { if edited { vault_modified = true; } }
                                  Err(e) => { eprintln!("{}\n", t!("errors.edit_note_failed", details = e.to_string()).red().bold()); }
                              }
                          }
                          Err(_) => {
                            eprintln!("{}", t!("errors.vault_lock_write_failed", details = "Notiz bearbeiten").red().bold());
                          }
                      }
                       update_last_activity(&app_state_arc);
                  } else { println!("{}", t!("messages.vault_is_locked").yellow()); }
             }
            "X" => {
                 cli::clear_screen()?;
                  match app_state_arc.read() {
                      Ok(state) => {
                          if !state.locked {
                               println!("{}", t!("messages.export_menu").cyan().bold());
                               println!("  [U] {}", t!("menu.export_unsafe_json"));
                               println!("  [C] {}", t!("menu.export_csv_unsafe"));
                               println!("  [E] {}", t!("menu.export_safe"));
                               println!("  [Z] {}", t!("actions.cancel").dimmed());
                               print!("\n{} ", t!("prompts.select_export_type"));
                               io::stdout().flush()?;
                               let mut export_type_input = String::new();
                               io::stdin().read_line(&mut export_type_input)?;
                               match export_type_input.trim().to_uppercase().as_str() {
                                    "U" => {
                                         match cli::export_vault_cli(&state.vault) {
                                             Ok(_) => {}
                                             Err(e) => eprintln!("{}\n", t!("errors.export_failed", details = e.to_string()).red().bold()),
                                         }
                                    },
                                    "C" => {
                                         match cli::export_vault_csv_cli(&state.vault) {
                                             Ok(_) => {}
                                             Err(e) => eprintln!("{}\n", t!("errors.export_failed", details = e.to_string()).red().bold()),
                                         }
                                    },
                                     "E" => {
                                         match cli::export_vault_encrypted_cli(&state.vault) {
                                             Ok(_) => {}
                                             Err(e) => eprintln!("{}\n", t!("errors.export_failed", details = e.to_string()).red().bold()),
                                         }
                                     },
                                    "Z" => println!("{}", t!("actions.cancelled").dimmed()),
                                    _ => println!("{}", t!("errors.invalid_choice").red()),
                               }
                                update_last_activity(&app_state_arc);
                          } else { println!("{}", t!("messages.vault_is_locked").yellow()); }
                      }
                      Err(_) => {
                        eprintln!("{}", t!("errors.vault_lock_read_failed", details = "Export").red().bold());
                      }
                  }
            }
            "I" => {
                cli::clear_screen()?;
                if !is_vault_locked(&app_state_arc) {
                    match app_state_arc.write() {
                        Ok(mut state) => {
                            println!("{}", t!("messages.import_menu").cyan().bold());
                            println!("  [U] {}", t!("menu.import_unsafe_json"));
                            println!("  [E] {}", t!("menu.import_safe"));
                            println!("  [Z] {}", t!("actions.cancel").dimmed());
                            print!("\n{} ", t!("prompts.select_import_type"));
                            io::stdout().flush()?;
                            let mut import_type_input = String::new();
                            io::stdin().read_line(&mut import_type_input)?;
                            match import_type_input.trim().to_uppercase().as_str() {
                                "U" => {
                                    match cli::import_vault_cli(&mut state.vault) {
                                        Ok(count) => { if count > 0 { vault_modified = true; } }
                                        Err(e) => eprintln!("{}\n", t!("errors.import_failed", details = e.to_string()).red().bold()),
                                    }
                                },
                                "E" => {
                                    match cli::import_vault_encrypted_cli(&mut state.vault) {
                                        Ok(count) => { if count > 0 { vault_modified = true; } }
                                        Err(e) => eprintln!("{}\n", t!("errors.import_failed", details = e.to_string()).red().bold()),
                                    }
                                },
                                "Z" => println!("{}", t!("actions.cancelled").dimmed()),
                                _ => println!("{}", t!("errors.invalid_choice").red()),
                            }
                        }
                        Err(_) => {
                            eprintln!("{}", t!("errors.vault_lock_write_failed", details = "Import").red().bold());
                        }
                    }
                     update_last_activity(&app_state_arc);
                } else { println!("{}", t!("messages.vault_is_locked").yellow()); }
            }
            "L" => {
                lock_app_state(&app_state_arc);
                println!("{}", t!("messages.vault_locked").green());
                action_performed_requires_wait = true;
            }
            "U" => {
                cli::clear_screen()?;
                if !is_vault_locked(&app_state_arc) {
                    println!("{}", t!("messages.vault_already_unlocked").yellow());
                } else {
                    match cli::unlock_vault_cli(&app_state_arc, &config_main) {
                        Ok(_) => {
                            println!("{}", t!("messages.vault_unlocked").green());
                            update_last_activity(&app_state_arc);
                        }
                        Err(VaultError::PasswordOrKeyfileVerification) => {
                            eprintln!("\n{}\n", t!("errors.master_password_or_keyfile_incorrect").red().bold());
                        }
                        Err(e) => {
                            eprintln!("{}\n", t!("errors.vault_unlock_failed_generic", details = e.to_string()).red().bold());
                        }
                    }
                }
            }
            "O" => {
                cli::clear_screen()?;
                cli::show_config_details_cli(&config_main);
            }
            "A" => {
                cli::clear_screen()?;
                match cli::manage_autolock_cli(&mut config_main) {
                    Ok(changed) => {
                        if changed {
                            if let Err(e) = config::save_config(&config_main) {
                                eprintln!("{}", t!("errors.config_save_failed_autolock", details = e.to_string()).red());
                            }
                        }
                    }
                    Err(e) => {
                         eprintln!("{}\n", t!("errors.manage_autolock_failed", details = e.to_string()).red().bold());
                    }
                }
                 update_last_activity(&app_state_arc);
            }
            "G" => {
                cli::clear_screen()?;
                 if !is_vault_locked(&app_state_arc) {
                    let default_opts = crypto::PasswordOptions::default();
                    let custom_symbols_from_config = config_main.password_generator_symbols.as_deref();
                    match crypto::generate_password_custom(&default_opts, custom_symbols_from_config) {
                        Ok(pw) => {
                            println!("{} {}", t!("messages.generated_password_prefix"), pw.green().bold());
                             if cli::prompt_yes_no(&t!("prompts.copy_to_clipboard"), Some(true))? {
                                if let Err(e) = cli::copy_to_clipboard(&pw) {
                                    eprintln!("{}", t!("errors.clipboard_copy_failed_manual", details=e.to_string()).yellow());
                                }
                             }
                        }
                        Err(e) => { eprintln!("{}\n", t!("errors.password_gen_failed", details = e.to_string()).red().bold()); }
                    }
                    update_last_activity(&app_state_arc);
                 } else {
                     println!("{}", t!("messages.vault_is_locked").yellow());
                 }
            }
            "8" => {
                cli::show_about(&config_main);
            }
            "9" => {
                if cli::prompt_yes_no(&t!("prompts.confirm_exit"), Some(true))? {
                    println!("{}", t!("cli.app.exiting").dimmed());
                    action_performed_requires_wait = false;
                    break;
                } else {
                    action_performed_requires_wait = false;
                }
            },
            "42" => {
                if is_vault_locked(&app_state_arc) {
                     println!("\n{}\n{}\n",
                        t!("game.locked_access_denied").red().bold(),
                        t!("game.locked_unlock_first").yellow()
                     );
                } else {
                    update_last_activity(&app_state_arc);
                    match game::start_game() {
                        Ok(_) => action_performed_requires_wait = false,
                        Err(e) => eprintln!("\n{}: {}", t!("errors.prefix").red(), e),
                    }
                }
                continue;
            },
            "16" => {
                       action_performed_requires_wait = true;
                       cli::check_password_strength_standalone()?;
            },
            "CHARLIE" => {
                cli::show_charlie_memorial_upgraded()?;
                action_performed_requires_wait = false;
                if !is_vault_locked(&app_state_arc) { update_last_activity(&app_state_arc); }
                continue;
            },
            "CIPHER" => {
                cli::run_cipher_challenge_upgraded()?;
                action_performed_requires_wait = false;
                if !is_vault_locked(&app_state_arc) { update_last_activity(&app_state_arc); }
                continue;
            },
            "BINARY" => {
                cli::show_binary_whispers_upgraded()?;
                action_performed_requires_wait = false;
                if !is_vault_locked(&app_state_arc) { update_last_activity(&app_state_arc); }
                continue;
            },
            _ => {
                println!("\n{}", t!("errors.invalid_choice").red());
                action_performed_requires_wait = true;
            }
        }

        if vault_modified && !is_vault_locked(&app_state_arc) {
            match app_state_arc.read() {
                Ok(state) => {
                    if let Some(key) = &state.key {
                        if let Err(e) = vault_logic::save_vault(&state.vault, key) {
                            eprintln!("\n{}\n{}\n{}",
                                t!("errors.critical_save_header").red().bold(),
                                t!("errors.critical_save_details", details = e.to_string()).red(),
                                t!("errors.critical_save_changes_lost").yellow()
                            );
                        } else {
                            println!("\n{}", t!("messages.vault_saved").green());
                        }
                    } else {
                        eprintln!("\n{}\n{}",
                            t!("errors.critical_save_header_locked").red().bold(),
                            t!("errors.critical_save_recommendation").yellow()
                        );
                    }
                }
                Err(_) => {
                     eprintln!("\n{}\n{}",
                        t!("errors.critical_save_lock_failed").red().bold(),
                        t!("errors.critical_save_changes_lost").yellow()
                    );
                }
            }
        } else if vault_modified && is_vault_locked(&app_state_arc) {
             eprintln!("{}", t!("errors.critical_save_header_locked").yellow().bold());
        }
        if action_performed_requires_wait {
            cli::wait_for_enter()?;
        }
    }
    if !is_vault_locked(&app_state_arc) {
        lock_app_state(&app_state_arc);
    }
    println!("{}", t!("messages.app_exit_success_farewell").green());
    Ok(())
}