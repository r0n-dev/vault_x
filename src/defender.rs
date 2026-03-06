use crate::config::{VAULT_FILE, CONFIG_FILE, DefenderSettings, HoneypotFileConfig};
use crate::errors::{VaultError, DefenderAlert, DefenderAlertReason, DefenderActionLevel};

use std::collections::HashSet;
use std::env;
use std::fs as std_fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use notify::{RecommendedWatcher, Watcher, RecursiveMode, event::AccessKind, event::EventKind as NotifyEventKind};
use hex;

use sysinfo::{System, SystemExt, ProcessExt, CpuExt, DiskExt, NetworkExt, NetworksExt};

use sha2::{Sha256, Digest};
use lazy_static::lazy_static;

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    System::Diagnostics::Debug::{IsDebuggerPresent, CheckRemoteDebuggerPresent, OutputDebugStringW},
    System::Threading::GetCurrentProcess,
    System::SystemInformation::{GetTickCount64, GetNativeSystemInfo, SYSTEM_INFO},
    UI::WindowsAndMessaging::FindWindowW,
    System::Memory::{
        VirtualQuery, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE_READ, PAGE_READWRITE, /* PAGE_WRITECOPY entfernt (Duplikat) */
        MEM_COMMIT, PAGE_GUARD, MEM_PRIVATE, PAGE_READONLY
    },
    Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN},
    Foundation::GetLastError,
};
#[cfg(target_os = "windows")]
use widestring::U16CString;
#[cfg(target_os = "windows")]
use std::ffi::c_void;

#[cfg(target_os = "linux")]
use std::fs as linux_fs;
#[cfg(target_os = "linux")]
use std::io::{BufReader as LinuxBufReader, BufRead as LinuxBufRead};
#[cfg(target_os = "linux")]
use libc::{ptrace, PTRACE_ATTACH, PTRACE_DETACH};


lazy_static! {
    static ref LOGGED_ONCE: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
    static ref CRITICAL_FUNCTION_POINTER: usize = critical_dummy_function as usize;
    static ref CRITICAL_FUNCTION_ORIGINAL_BYTES: Mutex<Option<Vec<u8>>> = Mutex::new(None);
}

fn log_once<F>(key: &str, log_fn: F) where F: FnOnce() {
    if let Ok(mut logged) = LOGGED_ONCE.lock() {
        if !logged.contains(key) {
            log_fn();
            logged.insert(key.to_string());
        }
    } else {
        log::error!("Defender: log_once Mutex vergiftet für Key: {}", key);
        log_fn();
    }
}

#[inline(never)]
fn critical_dummy_function() -> u32 {
    let a: u32 = 10;
    let b: u32 = 20;
    let mut result: u32 = a + b + 0xDEADBEEF;
    for i in 0u32..5 {
        result = result.wrapping_add(i);
    }
    result
}

fn initialize_critical_function_snapshot() {
    let func_ptr = *CRITICAL_FUNCTION_POINTER as *const u8;
    let snapshot_size = 32;

    if let Ok(mut original_bytes_guard) = CRITICAL_FUNCTION_ORIGINAL_BYTES.lock() {
        if original_bytes_guard.is_none() {
            let mut bytes = Vec::with_capacity(snapshot_size);
            #[cfg(target_os = "windows")]
            {
                 let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
                 if unsafe { VirtualQuery(func_ptr as *const c_void, &mut mem_info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) } != 0 {
                     if (mem_info.State & MEM_COMMIT) != 0 &&
                        (mem_info.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READWRITE | PAGE_READONLY)) != 0 {
                         unsafe {
                            let slice = std::slice::from_raw_parts(func_ptr, snapshot_size);
                            bytes.extend_from_slice(slice);
                         }
                         *original_bytes_guard = Some(bytes);
                         log::debug!("Defender: Snapshot der kritischen Dummy-Funktion erstellt ({} Bytes).", snapshot_size);
                     } else {
                         log::error!("Defender: Speicher für kritische Dummy-Funktion ({:p}) ist nicht lesbar/ausführbar oder committed. Kann Snapshot nicht erstellen. Protect: {:#X}, State: {:#X}", func_ptr, mem_info.Protect, mem_info.State);
                     }
                 } else {
                      let last_error = unsafe { GetLastError() };
                      log::error!("Defender: VirtualQuery fehlgeschlagen für kritische Dummy-Funktion ({:p}). Fehler: {}. Kann Snapshot nicht erstellen.", func_ptr, last_error);
                 }
            }
            #[cfg(not(target_os = "windows"))]
            {
                 unsafe {
                    let slice = std::slice::from_raw_parts(func_ptr, snapshot_size);
                    bytes.extend_from_slice(slice);
                 }
                 *original_bytes_guard = Some(bytes);
                 log::debug!("Defender: Snapshot der kritischen Dummy-Funktion erstellt ({} Bytes).", snapshot_size);
            }
        }
    } else {
        log::error!("Defender: Mutex für CRITICAL_FUNCTION_ORIGINAL_BYTES vergiftet. Kann Snapshot nicht erstellen.");
    }
}


fn map_level(level_str: &str) -> DefenderActionLevel {
    match level_str.to_lowercase().as_str() {
        "warn_user" => DefenderActionLevel::WarnUser,
        "warn_user_critical" => DefenderActionLevel::WarnUserCritical,
        "lock_vault" => DefenderActionLevel::LockVault,
        "shutdown" => DefenderActionLevel::Shutdown,
        _ => DefenderActionLevel::LogOnly,
    }
}

fn send_alert(tx: &mpsc::Sender<DefenderAlert>, reason: DefenderAlertReason, level: DefenderActionLevel) {
    let alert = DefenderAlert { reason: reason.clone(), suggested_action_level: level.clone() };
    if let Err(e) = tx.send(alert) {
        log::error!("Defender: Fehler beim Senden des Alerts '{:?}': {}", reason, e);
    } else {
        log::warn!("Defender: Alert gesendet -> Reason: {:?}, Suggested Level: {:?}", reason, level);
    }
}


mod anti_debug_checks {
    use super::*;
    const TIMING_CHECK_THRESHOLD_MS_UPPER: u128 = 300;
    const TIMING_CHECK_SLEEP_MS: u64 = 50;

    #[cfg(target_os = "windows")]
    fn windows_advanced_checks(tx: &mpsc::Sender<DefenderAlert>, settings: &DefenderSettings) {
        if !settings.enable_advanced_antidebug { return; }
        log_once("win_ad_advanced_check_start", || log::debug!("Defender (Win): Starte erweiterte Anti-Debug Checks..."));

        if settings.enable_win_peb_checks {
            unsafe {
                 #[cfg(target_arch = "x86_64")]
                 {
                     use std::arch::asm;
                     const TEB_GS_OFFSET: usize = 0x30;
                     const PEB_TEB_OFFSET: usize = 0x60;
                     const BEING_DEBUGGED_PEB_OFFSET: usize = 0x02;
                     const NT_GLOBAL_FLAG_PEB_OFFSET: usize = 0xBC;
                     const DEBUGGER_FLAGS_CHECK: u32 = 0x70;

                     let teb: *const u8;
                     asm!("mov {}, gs:[{}]", out(reg) teb, const TEB_GS_OFFSET, options(pure, nomem, nostack));

                     if !teb.is_null() {
                        let peb_ptr_addr = teb.add(PEB_TEB_OFFSET) as *const *const u8;
                        let peb: *const u8 = *peb_ptr_addr;

                        if !peb.is_null() {
                            let being_debugged_ptr = peb.add(BEING_DEBUGGED_PEB_OFFSET);
                            if *being_debugged_ptr != 0 {
                                log::warn!("Defender (Win64): PEB BeingDebugged Flag gesetzt.");
                                send_alert(tx, DefenderAlertReason::PebBeingDebuggedFlagDetected, map_level(&settings.debug_detection_level));
                            }

                            let nt_global_flag_ptr = peb.add(NT_GLOBAL_FLAG_PEB_OFFSET) as *const u32;
                            if (*nt_global_flag_ptr & DEBUGGER_FLAGS_CHECK) != 0 {
                                log::warn!("Defender (Win64): PEB NtGlobalFlag Debugger Flags gesetzt ({:#X}).", *nt_global_flag_ptr);
                                send_alert(tx, DefenderAlertReason::NtGlobalFlagDebuggedDetected, map_level(&settings.debug_detection_level));
                            }
                        } else { log_once("win_peb_is_null_64", || log::warn!("Defender (Win64): PEB-Zeiger aus TEB ist null."));}
                     } else { log_once("win_teb_is_null_64", || log::warn!("Defender (Win64): TEB-Zeiger via GS ist null."));}
                 }
                 #[cfg(target_arch = "x86")]
                 {
                    use std::arch::asm;
                    const TEB_FS_OFFSET: usize = 0x18;
                    const PEB_TEB_OFFSET: usize = 0x30;
                    const BEING_DEBUGGED_PEB_OFFSET: usize = 0x02;
                    const NT_GLOBAL_FLAG_PEB_OFFSET: usize = 0x68;
                    const DEBUGGER_FLAGS_CHECK: u32 = 0x70;

                    let teb: *const u8;
                    asm!("mov {}, fs:[{}]", out(reg) teb, const TEB_FS_OFFSET, options(pure, nomem, nostack));

                    if !teb.is_null() {
                        let peb_ptr_addr = teb.add(PEB_TEB_OFFSET) as *const *const u8;
                        let peb: *const u8 = *peb_ptr_addr;

                        if !peb.is_null() {
                            let being_debugged_ptr = peb.add(BEING_DEBUGGED_PEB_OFFSET);
                            if *being_debugged_ptr != 0 {
                                log::warn!("Defender (Win32): PEB BeingDebugged Flag gesetzt.");
                                send_alert(tx, DefenderAlertReason::PebBeingDebuggedFlagDetected, map_level(&settings.debug_detection_level));
                            }

                            let nt_global_flag_ptr = peb.add(NT_GLOBAL_FLAG_PEB_OFFSET) as *const u32;
                            if (*nt_global_flag_ptr & DEBUGGER_FLAGS_CHECK) != 0 {
                                log::warn!("Defender (Win32): PEB NtGlobalFlag Debugger Flags gesetzt ({:#X}).", *nt_global_flag_ptr);
                                send_alert(tx, DefenderAlertReason::NtGlobalFlagDebuggedDetected, map_level(&settings.debug_detection_level));
                            }
                        } else { log_once("win_peb_is_null_32", || log::warn!("Defender (Win32): PEB-Zeiger aus TEB ist null."));}
                    } else { log_once("win_teb_is_null_32", || log::warn!("Defender (Win32): TEB-Zeiger via FS ist null."));}
                 }
                 #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
                 {
                      log_once("win_peb_arch_not_impl", || log::warn!("Defender (Win): PEB-Checks für diese Architektur nicht implementiert."));
                 }
            }
        }

        if settings.enable_win_ntqueryinfo_check {
             log_once("win_ntqueryinfo_not_impl", || log::debug!("Defender (Win): NtQueryInformationProcess Check noch nicht vollständig implementiert."));
        }

        if settings.enable_win_outputdebugstring_check {
             if let Ok(test_string) = U16CString::from_str("VaultX_DebugTest_OutputDebugString") {
                let last_error_before = unsafe { GetLastError() };
                unsafe { OutputDebugStringW(test_string.as_ptr()); }
                let last_error_after = unsafe { GetLastError() };
                if last_error_before != 0 && last_error_after == 0 {
                    log::warn!("Defender (Win): Potenzieller Debugger durch OutputDebugString LastError-Verhalten erkannt.");
                }
                log_once("win_outputdebugstring_check_basic", || log::debug!("Defender (Win): OutputDebugString Check durchgeführt. LastError before: {}, after: {}", last_error_before, last_error_after));
             }
        }

        if unsafe { IsDebuggerPresent() } != 0 {
            log::warn!("Defender (Win): IsDebuggerPresent hat Debugger gemeldet.");
            send_alert(tx, DefenderAlertReason::DebuggerDetected("WinAPI IsDebuggerPresent".to_string()), map_level(&settings.debug_detection_level));
        }
        let mut is_remote_debugger_present: i32 = 0;
        let current_process_handle = unsafe { GetCurrentProcess() };
        if unsafe { CheckRemoteDebuggerPresent(current_process_handle, &mut is_remote_debugger_present) } != 0 {
            if is_remote_debugger_present != 0 {
                 log::warn!("Defender (Win): CheckRemoteDebuggerPresent hat Remote Debugger gemeldet.");
                send_alert(tx, DefenderAlertReason::DebuggerDetected("WinAPI CheckRemoteDebuggerPresent".to_string()), map_level(&settings.debug_detection_level));
            }
        } else {
             let last_error = unsafe { GetLastError() };
             if last_error != 0 {
                  log_once(&format!("win_checkremotedebuggerpresent_err_{}", last_error), || log::warn!("Defender (Win): Fehler bei CheckRemoteDebuggerPresent: {}", last_error));
             }
        }

        let start_time_tick = unsafe { GetTickCount64() };
        thread::sleep(Duration::from_millis(TIMING_CHECK_SLEEP_MS));
        let end_time_tick = unsafe { GetTickCount64() };
        let duration_ms_tick = (end_time_tick.wrapping_sub(start_time_tick)) as u128;

        if duration_ms_tick > TIMING_CHECK_THRESHOLD_MS_UPPER {
            log::warn!("Defender (Win): Timing-Anomalie erkannt (GetTickCount64). Erwartet ca. {}ms, Gemessen {}ms.", TIMING_CHECK_SLEEP_MS, duration_ms_tick);
            send_alert(tx, DefenderAlertReason::DebuggerDetected(format!("Timing Anomaly (GetTickCount64 {}ms, Actual {}ms)", TIMING_CHECK_SLEEP_MS, duration_ms_tick)), map_level(&settings.debug_detection_level));
        }

        const DEBUGGER_WINDOW_TITLES: [&str; 10] = ["OllyDbg", "x64dbg", "IDA", "Ghidra", "Cheat Engine", "Debugger", "Windbg", "dnSpy", "Immunity Debugger", "Radare2"];
        for title_part in DEBUGGER_WINDOW_TITLES {
            if let Ok(wide_title) = U16CString::from_str(title_part) {
                let hwnd = unsafe { FindWindowW(std::ptr::null_mut(), wide_title.as_ptr()) };
                if hwnd != 0 {
                     log::warn!("Defender (Win): Potenzielles Debugger-Fenster gefunden: '{}'.", title_part);
                    send_alert(tx, DefenderAlertReason::DebuggerDetected(format!("Potenzielles Debugger-Fenster gefunden: '{}'", title_part)), map_level(&settings.debug_detection_level));
                }
            }
        }
        log_once("win_ad_advanced_check_complete", || log::debug!("Defender (Win): Erweiterte Anti-Debug Checks abgeschlossen."));
    }

    #[cfg(target_os = "linux")]
    fn linux_advanced_checks(tx: &mpsc::Sender<DefenderAlert>, settings: &DefenderSettings) {
        if !settings.enable_advanced_antidebug { return; }
        log_once("linux_ad_advanced_check_start", || log::debug!("Defender (Linux): Starte erweiterte Anti-Debug Checks..."));

        match linux_fs::File::open("/proc/self/status") {
            Ok(file) => {
                let reader = LinuxBufReader::new(file);
                for line_result in reader.lines() {
                    if let Ok(line) = line_result {
                        if line.starts_with("TracerPid:") {
                            if let Some(pid_str) = line.split_whitespace().nth(1) {
                                if pid_str != "0" {
                                    log::warn!("Defender (Linux): TracerPid ungleich 0 gefunden: {}", pid_str);
                                    send_alert(tx, DefenderAlertReason::DebuggerDetected(format!("Linux TracerPid ({})", pid_str)), map_level(&settings.debug_detection_level));
                                }
                            }
                            break;
                        }
                    }
                }
            }
            Err(e) => log_once("linux_proc_status_err", || log::warn!("Defender (Linux): /proc/self/status nicht lesbar für TracerPid-Prüfung: {}", e)),
        }

        if settings.enable_linux_ptrace_check {
             let current_pid = unsafe { libc::getpid() };
             let attach_result = unsafe { ptrace(PTRACE_ATTACH, current_pid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) };
             if attach_result == -1 {
                 let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                 if errno == libc::EPERM {
                      log_once("linux_ptrace_eperm", || log::warn!("Defender (Linux): ptrace self-attach fehlgeschlagen (EPERM - Already Traced oder Berechtigungsproblem). Debugger erkannt?"));
                      send_alert(tx, DefenderAlertReason::LinuxPtraceAttached(errno), map_level(&settings.debug_detection_level));
                 } else if errno != 0 {
                     log_once(&format!("linux_ptrace_err_{}", errno), || log::trace!("Defender (Linux): ptrace self-attach fehlgeschlagen mit errno {}.", errno));
                 }
             } else {
                 unsafe { ptrace(PTRACE_DETACH, current_pid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) };
                 log_once("linux_ptrace_ok", || log::trace!("Defender (Linux): ptrace self-attach erfolgreich und detach durchgeführt."));
             }
        }

        let start_time = std::time::Instant::now();
        thread::sleep(Duration::from_millis(TIMING_CHECK_SLEEP_MS));
        let duration_ms = start_time.elapsed().as_millis();

        if duration_ms > TIMING_CHECK_THRESHOLD_MS_UPPER {
             log::warn!("Defender (Linux): Timing-Anomalie erkannt (Instant). Erwartet ca. {}ms, Gemessen {}ms.", TIMING_CHECK_SLEEP_MS, duration_ms);
             send_alert(tx, DefenderAlertReason::DebuggerDetected(format!("Timing Anomaly (Instant {}ms, Actual {}ms)", TIMING_CHECK_SLEEP_MS, duration_ms)), map_level(&settings.debug_detection_level));
        }
        log_once("linux_ad_advanced_check_complete", || log::debug!("Defender (Linux): Erweiterte Anti-Debug Checks abgeschlossen."));
    }

    pub fn perform(tx: &mpsc::Sender<DefenderAlert>, settings: &DefenderSettings) {
        let basic_check_required = map_level(&settings.debug_detection_level) > DefenderActionLevel::LogOnly;
        if !settings.enable_advanced_antidebug && !basic_check_required {
            log_once("adv_ad_disabled_and_basic_none", || log::info!("Defender: Anti-Debugging-Checks deaktiviert oder nur LogOnly und keine erweiterten Checks aktiv."));
            return;
        }
        if settings.enable_advanced_antidebug {
            log_once("performing_adv_ad", || log::info!("Defender: Führe erweiterte Anti-Debugging-Checks durch..."));
             #[cfg(target_os = "windows")]
             windows_advanced_checks(tx, settings);
             #[cfg(target_os = "linux")]
             linux_advanced_checks(tx, settings);
             #[cfg(not(any(target_os = "windows", target_os = "linux")))]
             log_once("adv_ad_unsupported_os", || log::warn!("Defender: Erweiterte Anti-Debugging-Checks für dieses OS nicht implementiert."));
        } else if basic_check_required {
             log_once("basic_ad_enabled_only", || log::debug!("Defender: Erweiterte Anti-Debugging-Checks deaktiviert, aber Basis-Checks sind (implizit durch Level > LogOnly) relevant."));
        }
    }
}

mod honeypot_handler {
    use super::*;
    fn create_honeypot_file(
        honeypot_config: &HoneypotFileConfig,
        honeypot_path: &Path,
        _tx: &mpsc::Sender<DefenderAlert>,
    ) -> Result<(), VaultError> {
        log::debug!("Defender: Erstelle Honeypot-Datei: {}", honeypot_path.display());
         if !honeypot_path.exists() {
             if let Some(parent_dir) = honeypot_path.parent() {
                 if !parent_dir.exists() {
                     std_fs::create_dir_all(parent_dir).map_err(VaultError::Io)?;
                     log::info!("Defender: Honeypot-Elternverzeichnis erstellt: {}", parent_dir.display());
                 }
             }
             let mut file = std_fs::File::create(honeypot_path).map_err(VaultError::Io)?;
             if let Some(content) = &honeypot_config.content_on_creation {
                 file.write_all(content.as_bytes()).map_err(VaultError::Io)?;
             }
             log::info!("Defender: Honeypot-Datei '{}' erstellt.", honeypot_path.display());
             #[cfg(target_os = "windows")]
             {
                 if let Ok(path_utf16) = U16CString::from_os_str(honeypot_path.as_os_str()){
                     let result = unsafe { SetFileAttributesW(path_utf16.as_ptr(), FILE_ATTRIBUTE_HIDDEN) };
                     if result == 0 {
                         log::warn!("Defender: Konnte Honeypot-Datei '{}' nicht als versteckt markieren. Fehler: {}", honeypot_path.display(), unsafe { GetLastError() });
                     } else {
                         log::debug!("Defender: Honeypot-Datei '{}' als versteckt markiert.", honeypot_path.display());
                     }
                 } else {
                      log::warn!("Defender: Konnte Pfad der Honeypot-Datei '{}' nicht in UTF-16 konvertieren, um sie zu verstecken.", honeypot_path.display());
                 }
             }
         } else {
             log::debug!("Defender: Honeypot-Datei '{}' existiert bereits.", honeypot_path.display());
         }
        Ok(())
    }

    pub fn setup_honeypots(
        settings: &DefenderSettings,
        watcher: &mut RecommendedWatcher,
        base_path: &Path,
        tx: &mpsc::Sender<DefenderAlert>,
    ) -> Result<(), VaultError> {
        if settings.honeypot_files.is_empty() {
            log_once("no_hps_cfg_setup", || log::info!("Defender: Keine Honeypot-Dateien für Setup konfiguriert."));
            return Ok(());
        }
        log_once("setup_hps_start", || log::debug!("Defender: Richte Honeypots ein..."));
        for hp_config in &settings.honeypot_files {
            let absolute_hp_path = if Path::new(&hp_config.path).is_absolute() {
                PathBuf::from(&hp_config.path)
            } else {
                base_path.join(&hp_config.path)
            };
            if let Err(e) = create_honeypot_file(hp_config, &absolute_hp_path, tx) {
                log::error!("Defender: Fehler beim Erstellen der Honeypot-Datei '{}': {}", absolute_hp_path.display(), e);
                continue;
            }
            if absolute_hp_path.exists() {
                match watcher.watch(&absolute_hp_path, RecursiveMode::NonRecursive) {
                    Ok(_) => log::info!("Defender: Überwache Honeypot-Datei: {}", absolute_hp_path.display()),
                    Err(e) => log::error!("Defender: Konnte Honeypot-Datei '{}' nicht überwachen: {}", absolute_hp_path.display(), e),
                }
            } else {
                 log::warn!("Defender: Honeypot-Datei '{}' konnte nach Erstellungsversuch nicht gefunden werden und wird nicht überwacht.", absolute_hp_path.display());
            }
        }
        Ok(())
    }
}

mod process_monitor {
    use super::*;
    pub fn scan_for_suspicious_processes(tx: &mpsc::Sender<DefenderAlert>, settings: &DefenderSettings, sys: &mut System) {
        if !settings.enable_suspicious_process_scan {
            log_once("susp_scan_disabled_scan_func", || log::info!("Defender: Scan nach verdächtigen Prozessen ist deaktiviert."));
            return;
        }
        log_once("performing_susp_scan_scan_func", || log::debug!("Defender: Scanne nach verdächtigen Prozessen..."));
        sys.refresh_processes();
        let mut found_processes_details = Vec::new();
        for (pid, process) in sys.processes() {
            let process_name_lower = process.name().to_lowercase();
            for suspicious_name_pattern in &settings.suspicious_process_names {
                if process_name_lower.contains(&suspicious_name_pattern.to_lowercase()) {
                    let detail = format!("PID: {}, Name: {}, Befehl: {:?}", pid, process.name(), process.cmd().join(" "));
                    log::warn!("Defender: Verdächtiger Prozess gefunden: {}", detail);
                    found_processes_details.push(detail);
                    break;
                }
            }
        }
        if !found_processes_details.is_empty() {
            send_alert(
                tx,
                DefenderAlertReason::SuspiciousProcessFound(
                    format!("{} verdächtige Prozesse erkannt.", found_processes_details.len()),
                    found_processes_details
                ),
                map_level(&settings.suspicious_process_scan_level)
            );
        } else {
            log_once("susp_scan_no_procs_found", || log::trace!("Defender: Keine verdächtigen Prozesse im aktuellen Scan gefunden."));
        }
    }

    pub fn check_parent_process(tx: &mpsc::Sender<DefenderAlert>, settings: &DefenderSettings, sys: &mut System) {
        if !settings.enable_suspicious_process_scan { return; }
        log_once("checking_parent_proc_start", || log::debug!("Defender: Überprüfe Elternprozess (Basis-Check)..."));
        sys.refresh_processes();
        if let Some(current_pid) = sysinfo::get_current_pid().ok() {
            if let Some(current_process) = sys.process(current_pid) {
                if let Some(parent_pid) = current_process.parent() {
                    if let Some(parent_process) = sys.process(parent_pid) {
                        let parent_name_lower = parent_process.name().to_lowercase();
                        for suspicious_name_pattern in &settings.suspicious_process_names {
                            if parent_name_lower.contains(&suspicious_name_pattern.to_lowercase()) {
                                let detail_current = format!("PID: {}, Name: {}", current_pid, current_process.name());
                                let detail_parent = format!("PID: {}, Name: {}", parent_pid, parent_process.name());
                                log::warn!("Defender: Verdächtiger Elternprozess '{}' für aktuellen Prozess '{}' gefunden.", detail_parent, detail_current);
                                send_alert(
                                    tx,
                                    DefenderAlertReason::ParentProcessSuspicious(detail_current, detail_parent),
                                    map_level(&settings.suspicious_process_scan_level)
                                );
                                break;
                            }
                        }
                    } else {
                        log_once("parent_proc_not_found", || log::trace!("Defender: Elternprozess mit PID {} nicht in Prozessliste gefunden.", parent_pid));
                    }
                } else {
                     log_once("no_parent_proc", || log::trace!("Defender: Aktueller Prozess hat keinen Elternprozess (oder kann nicht ermittelt werden)."));
                }
            }
        } else {
             log_once("current_pid_unavailable", || log::warn!("Defender: Aktuelle PID konnte nicht ermittelt werden für Elternprozess-Check."));
        }
    }

    #[cfg(target_os = "windows")]
    pub fn check_suspicious_process_handles_windows(_tx: &mpsc::Sender<DefenderAlert>, _settings: &DefenderSettings) {
        log_once("win_proc_handles_check_not_impl", || log::debug!("Defender (Win): Prüfung auf verdächtige Prozess-Handles (noch nicht implementiert)."));
    }
}

mod integrity_checks {
    use super::*;

    #[cfg(target_os = "windows")]
    pub fn check_code_sections_integrity_windows(_tx: &mpsc::Sender<DefenderAlert>, settings: &DefenderSettings) {
        if !(settings.enable_self_integrity_check && settings.enable_code_section_integrity_check) {
            log_once("win_code_section_check_disabled", || log::info!("Defender (Win): Integritätsprüfung der Code-Sektionen deaktiviert."));
            return;
        }
        log_once("win_code_section_check_not_impl", || log::debug!("Defender (Win): Integritätsprüfung der Code-Sektionen (PE-Header-Analyse, Hashing) noch nicht implementiert."));
    }

    #[cfg(target_os = "linux")]
    pub fn check_code_sections_integrity_linux(_tx: &mpsc::Sender<DefenderAlert>, settings: &DefenderSettings) {
        if !(settings.enable_self_integrity_check && settings.enable_code_section_integrity_check) {
            log_once("linux_code_section_check_disabled", || log::info!("Defender (Linux): Integritätsprüfung der Code-Sektionen deaktiviert."));
            return;
        }
        log_once("linux_code_section_check_not_impl", || log::debug!("Defender (Linux): Integritätsprüfung der Code-Sektionen (ELF-Header-Analyse, Hashing) noch nicht implementiert."));
    }

    pub fn check_executable_file_integrity(tx: &mpsc::Sender<DefenderAlert>, settings: &DefenderSettings) {
        if !settings.enable_executable_hash_check {
            log_once("exec_hash_check_disabled", || log::info!("Defender: Integritätsprüfung der ausführbaren Datei (Hash) deaktiviert."));
            return;
        }
        log_once("performing_exec_hash_check", || log::debug!("Defender: Führe Integritätsprüfung der ausführbaren Datei (Hash) durch..."));
        let expected_hash_hex = match &settings.expected_executable_hash_sha256 {
            Some(h) if !h.is_empty() => h.clone(),
            _ => {
                log_once("no_exp_hash_for_exec_check", || log::warn!("Defender: Kein erwarteter Hash für Integritätsprüfung der Executable konfiguriert. Überprüfung übersprungen."));
                return;
            }
        };
        match env::current_exe() {
            Ok(exe_path) => {
                match std_fs::File::open(&exe_path) {
                    Ok(mut file) => {
                        let mut hasher = Sha256::new();
                        let mut buffer = Vec::new();
                        if let Err(e) = file.read_to_end(&mut buffer) {
                            log::error!("Defender: Fehler beim Lesen der Executable '{}' für Hash: {}", exe_path.display(), e);
                            return;
                        }
                        hasher.update(&buffer);
                        let calculated_hash_bytes = hasher.finalize();
                        let calculated_hash_hex = hex::encode(calculated_hash_bytes);
                        if calculated_hash_hex.eq_ignore_ascii_case(&expected_hash_hex) {
                            log_once("exec_hash_integrity_ok", || log::debug!("Defender: Integritätsprüfung der Executable (Datei-Hash) erfolgreich."));
                        } else {
                            log::error!(
                                "Defender: Integrität der Executable '{}' kompromittiert (Datei-Hash). Erwartet: {}, Berechnet: {}",
                                exe_path.display(), expected_hash_hex, calculated_hash_hex
                            );
                            send_alert(
                                tx,
                                DefenderAlertReason::ExecutableHashMismatch {
                                    executable_path: exe_path.display().to_string(),
                                    expected_hash: expected_hash_hex,
                                    calculated_hash: calculated_hash_hex,
                                },
                                map_level(&settings.executable_hash_check_level)
                            );
                        }
                    }
                    Err(e) => {
                        log::error!("Defender: Konnte Executable '{}' für Hash-Prüfung nicht öffnen: {}", exe_path.display(), e);
                    }
                }
            }
            Err(e) => {
                log::error!("Defender: Konnte Pfad der aktuellen Executable für Integritätsprüfung nicht ermitteln: {}", e);
            }
        }
    }

    pub fn check_runtime_critical_function_integrity(tx: &mpsc::Sender<DefenderAlert>, settings: &DefenderSettings) {
        if !settings.enable_runtime_memory_integrity_check {
            log_once("runtime_crit_func_check_disabled", || log::info!("Defender: Laufzeit-Speicherprüfung (krit. Funktion) deaktiviert."));
            return;
        }
        log_once("performing_runtime_crit_func_check", || log::debug!("Defender: Führe Laufzeit-Speicherprüfung (krit. Funktion) durch..."));
        let func_ptr = *CRITICAL_FUNCTION_POINTER as *const u8;
        let original_bytes_guard = CRITICAL_FUNCTION_ORIGINAL_BYTES.lock().unwrap_or_else(|poisoned| {
            log::error!("Defender: Mutex für CRITICAL_FUNCTION_ORIGINAL_BYTES vergiftet beim Lesen!");
            poisoned.into_inner()
        });
        if let Some(original_bytes) = original_bytes_guard.as_ref() {
            if original_bytes.is_empty() {
                log_once("crit_func_empty_snapshot_runtime", || log::warn!("Defender: Snapshot der kritischen Funktion ist leer. Laufzeitprüfung übersprungen."));
                return;
            }
            let mut current_bytes_vec = Vec::with_capacity(original_bytes.len());
            unsafe {
                #[cfg(target_os = "windows")]
                {
                    let mut mem_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                    if VirtualQuery(func_ptr as *const c_void, &mut mem_info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) == 0 {
                        log::error!("Defender: VirtualQuery fehlgeschlagen für Adresse {:p} der kritischen Funktion. Laufzeitprüfung abgebrochen.", func_ptr);
                        return;
                    }
                    if mem_info.State != MEM_COMMIT || (mem_info.Protect & (PAGE_EXECUTE_READ | PAGE_READONLY | PAGE_READWRITE)) == 0 {
                        log::error!("Defender: Speicher für kritische Funktion bei {:p} nicht committed oder nicht lesbar. Laufzeitprüfung abgebrochen. Protect: {:#X}", func_ptr, mem_info.Protect);
                        return;
                    }
                }
                let slice = std::slice::from_raw_parts(func_ptr, original_bytes.len());
                current_bytes_vec.extend_from_slice(slice);
            }
            if current_bytes_vec != *original_bytes {
                let original_hex = hex::encode(original_bytes);
                let current_hex = hex::encode(&current_bytes_vec);
                log::error!(
                    "Defender: Speicher der kritischen Dummy-Funktion (Adresse: {:p}) wurde verändert! Original ({} Bytes): {}, Aktuell ({} Bytes): {}",
                    func_ptr, original_bytes.len(), original_hex, current_bytes_vec.len(), current_hex
                );
                send_alert(
                    tx,
                    DefenderAlertReason::RuntimeCriticalFunctionTampered {
                        function_address: format!("{:p}", func_ptr),
                        original_bytes_preview: original_hex.chars().take(16).collect::<String>() + "...",
                        current_bytes_preview: current_hex.chars().take(16).collect::<String>() + "...",
                    },
                    map_level(&settings.runtime_memory_integrity_check_level)
                );
            } else {
                log_once("runtime_crit_func_integrity_ok", || log::trace!("Defender: Laufzeit-Speicherprüfung der kritischen Funktion OK."));
            }
        } else {
            log_once("crit_func_no_snapshot_runtime", || log::warn!("Defender: Kein Snapshot der kritischen Funktion für Laufzeitprüfung verfügbar. Initialisierung fehlgeschlagen?"));
        }
    }

    pub fn check_unusual_memory_region(tx: &mpsc::Sender<DefenderAlert>, settings: &DefenderSettings) {
         if !settings.enable_unusual_memory_region_check {
            log_once("unusual_mem_check_disabled", || log::info!("Defender: Prüfung auf ungewöhnliche Speicherberechtigungen deaktiviert."));
            return;
         }
         log_once("performing_unusual_mem_check", || log::debug!("Defender: Führe Prüfung auf ungewöhnliche Speicherberechtigungen durch..."));
        #[cfg(target_os = "windows")]
        {
            log_once("win_unusual_mem_check", || log::debug!("Defender (Win): Prüfung auf ungewöhnliche Speicherberechtigungen..."));
            let mut base_address = 0 as *const c_void;
            let max_address = unsafe {
                 let mut sys_info: SYSTEM_INFO = std::mem::zeroed();
                 GetNativeSystemInfo(&mut sys_info);
                 sys_info.lpMaximumApplicationAddress
            };
            while (base_address as usize) < (max_address as usize) {
                let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
                let result = unsafe {
                    VirtualQuery(base_address, &mut mem_info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>())
                };
                if result == 0 {
                     let last_error = unsafe { GetLastError() };
                     if last_error != 0 && last_error != 87 {
                         log_once(&format!("win_virtualquery_err_{:p}_{}", base_address, last_error), || log::warn!("Defender (Win): VirtualQuery fehlgeschlagen bei Adresse {:p}: {}", base_address, last_error));
                     }
                     break;
                }
                let is_rwx = (mem_info.Protect & PAGE_EXECUTE_READWRITE) != 0;
                let is_execute_writecopy = (mem_info.Protect & PAGE_EXECUTE_WRITECOPY) != 0;
                if (is_rwx || is_execute_writecopy) && (mem_info.State & MEM_COMMIT) != 0 && (mem_info.Type & MEM_PRIVATE) != 0 && (mem_info.Protect & PAGE_GUARD) == 0 {
                     let reason = format!("Ungewöhnliche RWX/Execute-WriteCopy Speicherregion: Basis {:p}, Größe {:#X}, Protect {:#X}, State {:#X}, Type {:#X}",
                                          mem_info.BaseAddress, mem_info.RegionSize, mem_info.Protect, mem_info.State, mem_info.Type);
                     log::error!("Defender (Win): {}", reason);
                     let level_str = if !settings.integrity_check_level.is_empty() {
                        &settings.integrity_check_level
                     } else {
                        "warn_user_critical"
                     };
                     send_alert(tx, DefenderAlertReason::UnusualMemoryRegion(reason), map_level(level_str));
                }
                let next_address = unsafe { (mem_info.BaseAddress as *const u8).add(mem_info.RegionSize as usize) as *const c_void };
                 if mem_info.RegionSize == 0 || next_address <= base_address {
                      log::warn!("Defender (Win): Ungültige RegionSize ({}) oder BaseAddress nicht fortgeschritten bei {:p}. Breche Speicherprüfung ab.", mem_info.RegionSize, mem_info.BaseAddress);
                      break;
                 }
                base_address = next_address;
            }
             log_once("win_unusual_mem_check_done", || log::trace!("Defender (Win): Prüfung auf ungewöhnliche Speicherberechtigungen abgeschlossen."));
        }
        #[cfg(target_os = "linux")]
        {
            log_once("linux_unusual_mem_check", || log::debug!("Defender (Linux): Prüfung auf ungewöhnliche Speicherberechtigungen (/proc/self/maps)..."));
             match linux_fs::File::open("/proc/self/maps") {
                 Ok(file) => {
                     let reader = LinuxBufReader::new(file);
                     for line_result in reader.lines() {
                         if let Ok(line) = line_result {
                             let parts: Vec<&str> = line.split_whitespace().collect();
                             if parts.len() > 1 && parts[1].contains('r') && parts[1].contains('w') && parts[1].contains('x') && parts[1].contains('p') {
                                 if parts.len() > 5 && (parts[5] == "[stack]" || parts[5] == "[heap]") {
                                     continue;
                                 }
                                 let reason = format!("Potenziell ungewöhnliche RWX Speicherregion (Linux /proc/self/maps): {}", line);
                                 log::warn!("Defender (Linux): {}", reason);
                                 let level_str = if !settings.integrity_check_level.is_empty() {
                                    &settings.integrity_check_level
                                 } else {
                                    "warn_user"
                                 };
                                 send_alert(tx, DefenderAlertReason::UnusualMemoryRegion(reason), map_level(level_str));
                             }
                         }
                     }
                 }
                 Err(e) => log_once("linux_proc_maps_err", || log::warn!("Defender (Linux): /proc/self/maps nicht lesbar für Speicherprüfung: {}", e)),
             }
             log_once("linux_unusual_mem_check_done", || log::trace!("Defender (Linux): Prüfung auf ungewöhnliche Speicherberechtigungen abgeschlossen."));
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
         log_once("unusual_mem_check_unsupported_os", || log::debug!("Defender: Prüfung auf ungewöhnliche Speicherberechtigungen für dieses OS nicht implementiert."));
    }

    #[cfg(target_os = "windows")]
    pub fn check_hardware_breakpoints_windows(_tx: &mpsc::Sender<DefenderAlert>, _settings: &DefenderSettings) {
        log_once("win_hw_bp_check_not_impl", || log::debug!("Defender (Win): Prüfung auf Hardware-Breakpoints (noch nicht implementiert - erfordert hohe Privilegien)."));
    }

    #[cfg(target_os = "windows")]
    pub fn check_common_api_hooks_windows(_tx: &mpsc::Sender<DefenderAlert>, _settings: &DefenderSettings) {
        log_once("win_api_hook_check_not_impl", || log::debug!("Defender (Win): Prüfung auf API Hooks (noch nicht implementiert)."));
    }
}

mod vm_detection {
    use super::*;
    pub fn detect_vm(tx: &mpsc::Sender<DefenderAlert>, settings: &DefenderSettings, sys: &mut System) {
        if !settings.enable_vm_detection {
            log_once("vm_detect_disabled_func", || log::info!("Defender: VM-Erkennung deaktiviert."));
            return;
        }
        log_once("performing_vm_detect_func", || log::debug!("Defender: Führe VM-Erkennungs-Checks durch..."));
        sys.refresh_disks_list();
        sys.refresh_networks_list();
        let mut vm_indicators = Vec::new();
        const VM_DISK_NAMES: [&str; 5] = ["vbox", "vmware", "virtual", "qemu", "hyper-v"];
        for disk in sys.disks() {
            let name_osstr = disk.name();
            let name_lower = name_osstr.to_string_lossy().to_lowercase();
            for vm_pattern in VM_DISK_NAMES {
                if name_lower.contains(vm_pattern) {
                    let indicator = format!("VM-verdächtiger Festplattenname: {}", name_lower);
                    log::warn!("Defender: {}", indicator);
                    vm_indicators.push(indicator);
                    break;
                }
            }
        }
        const VM_MAC_PREFIXES: [&str; 6] = [
            "00:05:69", "00:0C:29", "00:1C:14", "00:50:56", "08:00:27", "52:54:00",
        ];
        if sys.networks().iter().next().is_none() {
             log_once("vm_detect_network_check_no_data", || log::warn!("Defender: Keine Netzwerkadapter-Daten für VM-Erkennung via MAC verfügbar. Wurden Netzwerkinformationen geladen?"));
        } else {
            for (_if_name, network) in sys.networks() {
                let mac_addr_str = network.mac_address().to_string().to_uppercase();
                for prefix in VM_MAC_PREFIXES {
                    if mac_addr_str.starts_with(prefix) {
                        let indicator = format!("VM-verdächtige MAC-Adresse: {} auf Adapter '{}'", mac_addr_str, _if_name);
                        log::warn!("Defender: {}", indicator);
                        vm_indicators.push(indicator);
                        break;
                    }
                }
            }
        }
        let global_cpu_info = sys.global_cpu_info();
        let cpu_brand_lower = global_cpu_info.brand().to_lowercase();
        const VM_CPU_PATTERNS: [&str; 3] = ["qemu", "virtual cpu", "xen"];
        for pattern in VM_CPU_PATTERNS {
            if cpu_brand_lower.contains(pattern) {
                let indicator = format!("VM-verdächtiger CPU-Name: {}", global_cpu_info.brand());
                log::warn!("Defender: {}", indicator);
                vm_indicators.push(indicator);
                break;
            }
        }
        #[cfg(target_os = "windows")]
        {
            const VM_ENV_VARS_WINDOWS: [(&str, Option<&str>); 2] = [
                ("VBOX_INSTALL_PATH", None),
                ("NUMBER_OF_PROCESSORS", Some("1")),
            ];
            for (var_name, expected_value_opt) in VM_ENV_VARS_WINDOWS {
                 match env::var(var_name) {
                     Ok(value) => {
                         if expected_value_opt.map_or(true, |ev| value.eq_ignore_ascii_case(ev)) {
                             let indicator = format!("VM-verdächtige Umgebungsvariable: {}='{}'", var_name, value);
                             log::warn!("Defender: {}", indicator);
                             vm_indicators.push(indicator);
                         }
                     }
                     Err(_) => {}
                 }
            }
        }
        if !vm_indicators.is_empty() {
            let summary = format!("{} VM-Indikator(en) gefunden.", vm_indicators.len());
            log::error!("Defender: {}", summary);
            send_alert(
                tx,
                DefenderAlertReason::VMDetected(format!("{} - Details: {:?}", summary, vm_indicators)),
                map_level(&settings.vm_detection_level)
            );
        } else {
            log_once("no_vm_indicators_found_func", || log::trace!("Defender: Keine VM-Indikatoren durch Standard-Checks gefunden."));
        }
    }
}

mod environment_checks {
    use super::*;
    pub fn check_suspicious_env_vars(tx: &mpsc::Sender<DefenderAlert>, settings: &DefenderSettings) {
        log_once("env_var_check_start", || log::debug!("Defender: Prüfe auf verdächtige Umgebungsvariablen..."));
        const SUSPICIOUS_ENV_VARS: [(&str, Option<&str>); 4] = [
            ("LD_PRELOAD", None), ("DYLD_INSERT_LIBRARIES", None),
            ("_NT_SYMBOL_PATH", None), ("ENABLE_CORPROFILER", Some("1")),
        ];
        let mut found_vars = Vec::new();
        for (var_name, expected_value_opt) in SUSPICIOUS_ENV_VARS {
            match env::var(var_name) {
                Ok(value) => {
                    if expected_value_opt.map_or(true, |ev| value.eq_ignore_ascii_case(ev)) {
                        let detail = format!("Variable: '{}', Wert: '{}'", var_name, value);
                        log::warn!("Defender: Verdächtige Umgebungsvariable gefunden: {}", detail);
                        found_vars.push(detail);
                    }
                }
                Err(env::VarError::NotPresent) => {}
                Err(env::VarError::NotUnicode(_)) => {
                    log::warn!("Defender: Umgebungsvariable '{}' enthält nicht-Unicode Daten.", var_name);
                }
            }
        }
        if !found_vars.is_empty() {
            let summary = format!("{} verdächtige Umgebungsvariable(n) erkannt.", found_vars.len());
            send_alert(
                tx,
                DefenderAlertReason::SuspiciousEnvironmentVariable(
                    summary.clone(),
                    found_vars.join("; ")
                ),
                map_level(&settings.debug_detection_level)
            );
        } else {
             log_once("no_susp_env_vars_found", || log::trace!("Defender: Keine verdächtigen Umgebungsvariablen gefunden."));
        }
    }
}

mod network_monitor {
    use super::*;
    use std::net::TcpStream;
    pub fn check_common_ports(tx: &mpsc::Sender<DefenderAlert>, settings: &DefenderSettings) {
        if !settings.enable_advanced_antidebug { return; }
        log_once("net_common_ports_check_start", || log::debug!("Defender: Prüfe auf verdächtige offene Ports (lokal)..."));
        const DEBUGGER_PORTS: [u16; 3] = [2600, 1234, 23946];
        let mut found_ports = Vec::new();
        for port in DEBUGGER_PORTS {
            if TcpStream::connect_timeout(&std::net::SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(100)).is_ok() {
                let detail = format!("Potenziell verdächtiger lokaler Port offen: {}", port);
                log::warn!("Defender: {}", detail);
                found_ports.push(detail);
            }
        }
        if !found_ports.is_empty() {
            send_alert(
                tx,
                DefenderAlertReason::DebuggerDetected(format!("Verdächtige Ports offen: {:?}", found_ports)),
                map_level(&settings.debug_detection_level)
            );
        } else {
            log_once("no_susp_ports_found", || log::trace!("Defender: Keine der Standard-Debugger-Ports scheinen lokal offen zu sein."));
        }
    }
}

pub fn initialize_defender_massively(
    settings_arc: Arc<DefenderSettings>,
    tx_main: mpsc::Sender<DefenderAlert>,
) -> Result<Option<RecommendedWatcher>, VaultError> {
    log::info!("Defender (Massive Ausbaustufe) wird initialisiert...");
    initialize_critical_function_snapshot();
    let initial_settings_clone = settings_arc.clone();
    let initial_tx_clone = tx_main.clone();
    thread::spawn(move || {
        log::debug!("Defender: Führe initiale Sicherheitschecks nach Start aus...");
        let mut sys = System::new_all();
        sys.refresh_all();
        let s = initial_settings_clone.as_ref();
        anti_debug_checks::perform(&initial_tx_clone, s);
        process_monitor::scan_for_suspicious_processes(&initial_tx_clone, s, &mut sys);
        process_monitor::check_parent_process(&initial_tx_clone, s, &mut sys);
        vm_detection::detect_vm(&initial_tx_clone, s, &mut sys);
        environment_checks::check_suspicious_env_vars(&initial_tx_clone, s);
        network_monitor::check_common_ports(&initial_tx_clone, s);
        integrity_checks::check_executable_file_integrity(&initial_tx_clone, s);
        integrity_checks::check_runtime_critical_function_integrity(&initial_tx_clone, s);
        integrity_checks::check_unusual_memory_region(&initial_tx_clone, s);
        #[cfg(target_os = "windows")]
        {
            process_monitor::check_suspicious_process_handles_windows(&initial_tx_clone, s);
            integrity_checks::check_hardware_breakpoints_windows(&initial_tx_clone, s);
            integrity_checks::check_common_api_hooks_windows(&initial_tx_clone, s);
            integrity_checks::check_code_sections_integrity_windows(&initial_tx_clone, s);
        }
        #[cfg(target_os = "linux")]
        {
            integrity_checks::check_code_sections_integrity_linux(&initial_tx_clone, s);
        }
        log::info!("Defender: Initiale Sicherheitschecks abgeschlossen.");
    });

    if settings_arc.enable_realtime_file_monitoring || !settings_arc.honeypot_files.is_empty() {
        log::info!("Defender: Echtzeit-Dateiüberwachung und/oder Honeypots sind aktiviert. Starte Watcher...");
        let watcher_settings_clone = settings_arc.clone();
        let watcher_tx_clone = tx_main.clone();
        let (event_tx, event_rx) = mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            if let Ok(event) = res {
                if event_tx.send(event).is_err() {
                    log::error!("Defender: Fehler beim Senden des notify-Events an den Channel (Empfänger weg?).");
                }
            } else if let Err(e) = res {
                log::error!("Defender: Fehler im notify Watcher: {}", e);
            }
        }).map_err(|e| VaultError::ConfigError(format!("Notify Watcher konnte nicht erstellt werden: {}",e)))?;
        let base_path_for_watcher = env::current_dir().map_err(VaultError::Io)?;
        if settings_arc.enable_realtime_file_monitoring {
            let critical_files_to_watch = [
                base_path_for_watcher.join(VAULT_FILE),
                base_path_for_watcher.join(CONFIG_FILE),
            ];
            for path in critical_files_to_watch.iter() {
                if path.exists() {
                    watcher.watch(path, RecursiveMode::NonRecursive)
                           .map_err(|e| VaultError::ConfigError(format!("Konnte Datei '{}' nicht überwachen: {}", path.display(), e)))?;
                    log::info!("Defender: Überwache kritische Datei: {}", path.display());
                } else {
                    log::warn!("Defender: Kritische Datei {} nicht gefunden, kann nicht überwacht werden.", path.display());
                }
            }
        }
        honeypot_handler::setup_honeypots(&settings_arc, &mut watcher, &base_path_for_watcher, &watcher_tx_clone)?;
        thread::spawn(move || {
            log::info!("Defender: Dateiüberwachungs-Event-Verarbeitungs-Thread gestartet.");
            for event in event_rx {
                log::trace!("Defender: Dateisystem-Event empfangen: {:?}", event);
                let settings_ref = watcher_settings_clone.as_ref();
                let relevant_paths: Vec<PathBuf> = event.paths.iter().filter_map(|p| {
                    if p.file_name().map_or(false, |name| name.to_string_lossy().starts_with('.') || name.to_string_lossy().ends_with(".tmp")) {
                        None
                    } else {
                        Some(p.clone())
                    }
                }).collect();
                if relevant_paths.is_empty() { continue; }
                for hp_config in &settings_ref.honeypot_files {
                    let absolute_hp_path = if Path::new(&hp_config.path).is_absolute() {
                        PathBuf::from(&hp_config.path)
                    } else {
                        base_path_for_watcher.join(&hp_config.path)
                    };
                    if relevant_paths.iter().any(|p| p.starts_with(&absolute_hp_path)) {
                        let action_description = match event.kind {
                            NotifyEventKind::Access(AccessKind::Close(notify::event::AccessMode::Write)) => "Schreibzugriff (geschlossen)".to_string(),
                            NotifyEventKind::Access(_) => "Lesezugriff/Anderer Zugriff".to_string(),
                            NotifyEventKind::Create(_) => "Erstellung".to_string(),
                            NotifyEventKind::Modify(_) => "Modifikation".to_string(),
                            NotifyEventKind::Remove(_) => "Entfernung".to_string(),
                            _ => "Unbekannte Aktion".to_string(),
                        };
                        log::warn!("Defender: HONEYPOT '{}' ausgelöst durch Aktion '{}' auf {:?}", hp_config.path, action_description, relevant_paths);
                        send_alert(
                            &watcher_tx_clone,
                            DefenderAlertReason::HoneypotTriggered(absolute_hp_path.clone(), action_description.clone()),
                            map_level(&settings_ref.vm_detection_level)
                        );
                    }
                }
                if settings_ref.enable_realtime_file_monitoring {
                    let critical_files_monitored = [
                        base_path_for_watcher.join(VAULT_FILE),
                        base_path_for_watcher.join(CONFIG_FILE),
                    ];
                    for crit_path in critical_files_monitored.iter() {
                        if relevant_paths.iter().any(|p| p == crit_path) {
                             let action_kind_str = match event.kind {
                                NotifyEventKind::Modify(_) | NotifyEventKind::Access(AccessKind::Close(notify::event::AccessMode::Write)) => "Modifiziert",
                                NotifyEventKind::Remove(_) => "Gelöscht",
                                _ => continue,
                            };
                            log::error!("Defender: KRITISCHE DATEI '{}' wurde '{}'!", crit_path.display(), action_kind_str);
                            send_alert(
                                &watcher_tx_clone,
                                DefenderAlertReason::CriticalFileModified(crit_path.clone(), action_kind_str.to_string()),
                                DefenderActionLevel::Shutdown
                            );
                        }
                    }
                }
            }
            log::info!("Defender: Dateiüberwachungs-Event-Verarbeitungs-Thread beendet.");
        });
        log::info!("Defender: Dateiüberwachungs-Setup erfolgreich gestartet.");
        Ok(Some(watcher))
    } else {
        log::info!("Defender: Echtzeit-Dateiüberwachung und Honeypots sind deaktiviert. Kein Watcher gestartet.");
        Ok(None)
    }
}