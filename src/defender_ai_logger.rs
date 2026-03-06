use crate::config::{DefenderSettings, CONFIG_FILE, VAULT_FILE};
use crate::errors::{DefenderActionLevel, DefenderAlert, DefenderAlertReason};
use crate::models::AppState;
use crate::defender as guardian;

use log::{debug, error, info, trace, warn};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::env;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{Pid, PidExt, ProcessExt, System, SystemExt, UserExt};
use zeroize::Zeroize;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

const ANALYSIS_INTERVAL: Duration = Duration::from_secs(2);
const LEARNING_PHASE_SECONDS: u64 = 300;
const SCORE_DECAY_FACTOR: f32 = 0.97;
const MAX_EVENT_HISTORY: usize = 200;

const CPU_HISTORY_LENGTH: usize = 30;
const NETWORK_HISTORY_LENGTH: usize = 100;
const HIGH_CPU_THRESHOLD: f32 = 80.0;
const CPU_DEVIATION_SIGMA: f32 = 6.0;
const BEACONING_INTERVAL_TOLERANCE: Duration = Duration::from_secs(1);
const MIN_BEACONING_COUNT: usize = 5;
const ABNORMAL_PORT_THRESHOLD: usize = 10;

#[derive(Debug, Clone)]
pub enum ExternalEvent {
    FileAccess {
        path: PathBuf,
        process_id: Option<u32>,
        access_type: String,
        details: Option<String>,
    },
    RegistryAccess {
        key_path: String,
        process_id: Option<u32>,
        access_type: String,
        value_name: Option<String>,
        value_data: Option<String>,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    Benign,
    Informational,
    Suspicious,
    HighRisk,
    Imminent,
    Compromised,
}

impl ThreatLevel {
    fn from_score(score: u32) -> Self {
        match score {
            0 => Self::Benign,
            1..=29 => Self::Informational,
            30..=69 => Self::Suspicious,
            70..=119 => Self::HighRisk,
            120..=179 => Self::Imminent,
            _ => Self::Compromised,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Indicator {
    LaunchedFromTempDir,
    LaunchedFromDownloadsDir,
    LaunchedFromRecycleBin,
    PathNotInBaseline,
    NameInThreatIntel,
    CmdlineContainsSuspiciousArgs(String),
    CmdlineObfuscated(String),
    ParentProcessIsUnusual(String),
    ProcessIsOrphaned,
    MasqueradingAsSystemProcess,
    ExecutionFromADS,
    PpidSpoofingCandidate,

    SustainedHighCpuUsage,
    AnomalousCpuSpike,
    AnomalousMemoryUsage,
    AbnormallyLargeProcessMemory,

    ConnectionToBlacklistedIp(String),
    NetworkBeaconingDetected,
    UnusualPortBinding(u16),
    DnsQueryToSuspiciousDomain(String),
    DnsQueryToDynamicDnsProvider,
    ConnectionToNewIp,
    HighVolumeOfFailedConnections,
    ProcessBindsToMultipleUnusualPorts,
    RawSocketUsage,

    CorrelatedWithCriticalFileWrite(String),
    AccessToUnusualSystemFile(String),
    CreatesExecutableInTemp,
    CreatesScriptFileWithSuspiciousContent,
    MassFileRenamingOrDeletion,
    ModificationOfBrowserDatabases,
    AccessToSshKeys,

    RegistryAutorunPersistence(String),
    ScheduledTaskCreation,
    NewServiceCreation,
    WmiPersistenceEventTrigger,

    AttemptToDisableSecurityTool,
    ClearingSystemLogs,
    TimeStompingOnFile,

    ProcessHollowingCandidate,
    CredentialDumpingFromMemory,
    CodeInjectionDetected(String),
    FollowsMaliciousAttackChain(String),
}

impl Indicator {
    fn score(&self) -> u32 {
        match self {
            Self::NameInThreatIntel => 150,
            Self::CorrelatedWithCriticalFileWrite(_) => 140,
            Self::ProcessHollowingCandidate => 130,
            Self::CredentialDumpingFromMemory => 160,
            Self::CodeInjectionDetected(_) => 140,
            Self::RegistryAutorunPersistence(_) => 100,
            Self::ConnectionToBlacklistedIp(_) => 90,
            Self::FollowsMaliciousAttackChain(_) => 80,
            Self::AttemptToDisableSecurityTool => 110,

            Self::CmdlineObfuscated(_) => 85,
            Self::MasqueradingAsSystemProcess => 75,
            Self::LaunchedFromTempDir => 60,
            Self::CmdlineContainsSuspiciousArgs(_) => 70,
            Self::WmiPersistenceEventTrigger => 95,
            Self::NewServiceCreation => 85,
            Self::ClearingSystemLogs => 90,

            Self::ParentProcessIsUnusual(_) => 65,
            Self::SustainedHighCpuUsage => 55,
            Self::NetworkBeaconingDetected => 60,
            Self::ScheduledTaskCreation => 60,
            Self::CreatesExecutableInTemp => 50,
            Self::AccessToUnusualSystemFile(_) => 55,
            Self::DnsQueryToSuspiciousDomain(_) => 45,
            Self::ModificationOfBrowserDatabases => 70,
            Self::AccessToSshKeys => 65,

            Self::PathNotInBaseline => 30,
            Self::AnomalousCpuSpike => 35,
            Self::AnomalousMemoryUsage => 30,
            Self::ProcessIsOrphaned => 25,
            Self::UnusualPortBinding(_) => 20,
            Self::ConnectionToNewIp => 15,
            Self::DnsQueryToDynamicDnsProvider => 25,
            Self::LaunchedFromDownloadsDir => 20,
            _ => 10,
        }
    }
}

impl fmt::Display for Indicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LaunchedFromTempDir => write!(f, "Prozess aus Temp-Verzeichnis gestartet"),
            Self::LaunchedFromDownloadsDir => write!(f, "Prozess aus Downloads-Verzeichnis gestartet"),
            Self::LaunchedFromRecycleBin => write!(f, "Prozess aus Papierkorb gestartet"),
            Self::PathNotInBaseline => write!(f, "Prozesspfad nicht in der Verhaltens-Baseline"),
            Self::NameInThreatIntel => write!(f, "Prozessname in Threat-Intel-DB gefunden"),
            Self::CmdlineContainsSuspiciousArgs(arg) => write!(f, "Verdächtiges CMD-Argument: '{}'", arg),
            Self::CmdlineObfuscated(tech) => write!(f, "Verschleierte Befehlszeile erkannt (Technik: {})", tech),
            Self::ParentProcessIsUnusual(parent) => write!(f, "Verdächtiger Elternprozess: '{}'", parent),
            Self::ProcessIsOrphaned => write!(f, "Ist ein verwaister Prozess ohne bekannten Elternteil"),
            Self::MasqueradingAsSystemProcess => write!(f, "Täuscht vor, ein Systemprozess zu sein (z.B. svchost.exe)"),
            Self::ExecutionFromADS => write!(f, "Ausführung aus einem Alternate Data Stream (ADS)"),
            Self::PpidSpoofingCandidate => write!(f, "Kandidat für Parent Process ID Spoofing"),
            Self::SustainedHighCpuUsage => write!(f, "Anhaltend hohe CPU-Auslastung"),
            Self::AnomalousCpuSpike => write!(f, "Statistisch anomaler CPU-Spike"),
            Self::AnomalousMemoryUsage => write!(f, "Anomaler Speicherverbrauch im Vergleich zur Baseline"),
            Self::AbnormallyLargeProcessMemory => write!(f, "Ungewöhnlich hoher Speicherverbrauch (>1GB)"),
            Self::ConnectionToBlacklistedIp(ip) => write!(f, "Netzwerkverbindung zu geblacklisteter IP: {}", ip),
            Self::NetworkBeaconingDetected => write!(f, "Verdächtiges Netzwerk-Beaconing-Muster erkannt"),
            Self::UnusualPortBinding(port) => write!(f, "Bindet an einen unüblichen Port: {}", port),
            Self::DnsQueryToSuspiciousDomain(domain) => write!(f, "DNS-Anfrage für verdächtige Domain: {}", domain),
            Self::DnsQueryToDynamicDnsProvider => write!(f, "DNS-Anfrage an einen Dynamic DNS Provider"),
            Self::ConnectionToNewIp => write!(f, "Baut Verbindung zu einer neuen, unbekannten IP auf"),
            Self::HighVolumeOfFailedConnections => write!(f, "Hohe Anzahl an fehlgeschlagenen Netzwerkverbindungen"),
            Self::ProcessBindsToMultipleUnusualPorts => write!(f, "Prozess lauscht auf vielen unüblichen Ports"),
            Self::RawSocketUsage => write!(f, "Verwendet Raw Sockets, möglicherweise für Packet Crafting"),
            Self::CorrelatedWithCriticalFileWrite(file) => write!(f, "Korreliert mit Schreibzugriff auf kritische Datei: {}", file),
            Self::AccessToUnusualSystemFile(file) => write!(f, "Greift auf ungewöhnliche Systemdatei zu: {}", file),
            Self::CreatesExecutableInTemp => write!(f, "Erstellt eine ausführbare Datei in einem Temp-Verzeichnis"),
            Self::CreatesScriptFileWithSuspiciousContent => write!(f, "Erstellt Skriptdatei (.ps1, .vbs) mit verdächtigem Inhalt"),
            Self::MassFileRenamingOrDeletion => write!(f, "Führt Massen-Umbenennung oder -Löschung von Dateien durch"),
            Self::ModificationOfBrowserDatabases => write!(f, "Modifiziert Browser-Datenbanken (Passwörter, Cookies)"),
            Self::AccessToSshKeys => write!(f, "Greift auf SSH-Schlüsselverzeichnisse zu (.ssh)"),
            Self::RegistryAutorunPersistence(key) => write!(f, "Persistenz durch Autostart-Registry-Schlüssel: {}", key),
            Self::ScheduledTaskCreation => write!(f, "Erstellt einen neuen geplanten Task (Scheduled Task)"),
            Self::NewServiceCreation => write!(f, "Installiert einen neuen System-Dienst"),
            Self::WmiPersistenceEventTrigger => write!(f, "Richtet WMI-Event-Trigger für Persistenz ein"),
            Self::AttemptToDisableSecurityTool => write!(f, "Versucht, einen bekannten Sicherheitsprozess zu beenden"),
            Self::ClearingSystemLogs => write!(f, "Versucht, System-Event-Logs zu löschen"),
            Self::TimeStompingOnFile => write!(f, "Manipuliert Zeitstempel einer Datei (Time-Stomping)"),
            Self::ProcessHollowingCandidate => write!(f, "Kandidat für Process Hollowing (manipulierter Speicher)"),
            Self::CredentialDumpingFromMemory => write!(f, "Potenzieller Diebstahl von Anmeldeinformationen aus dem Speicher (lsass)"),
            Self::CodeInjectionDetected(target) => write!(f, "Code-Injektion in einen anderen Prozess erkannt (Ziel: {})", target),
            Self::FollowsMaliciousAttackChain(name) => write!(f, "Folgt bekannter Angriffskette: '{}'", name),
        }
    }
}


#[derive(Debug, Default, Clone)]
struct CpuBaseline {
    avg_usage: f32,
    std_deviation: f32,
    samples: u64,
}

#[derive(Debug, Clone)]
struct NetworkConnectionRecord {
    timestamp: Instant,
    remote_ip: IpAddr,
    remote_port: u16,
    protocol: String,
}

#[derive(Debug, Clone)]
struct FileOperationRecord {
    timestamp: Instant,
    path: PathBuf,
    operation: String,
}

#[derive(Debug, Default, Clone)]
struct BehaviorBaseline {
    known_remote_ips: HashSet<IpAddr>,
    known_ports: HashSet<u16>,
    common_parent_processes: HashSet<String>,
    typical_cmd_line_args: HashSet<String>,
    accessed_file_paths: HashSet<PathBuf>,
    cpu_baseline: CpuBaseline,
    samples: u64,
}

#[derive(Debug, Clone)]
struct ThreatProfile {
    pid: Pid,
    name: String,
    path: PathBuf,
    cmdline: Vec<String>,
    parent: Option<Pid>,
    user_id: Option<String>,
    
    indicators: HashSet<Indicator>,
    score: u32,
    current_level: ThreatLevel,
    last_level_triggered: ThreatLevel,
    first_seen: Instant,
    
    cpu_history: VecDeque<f32>,
    network_history: VecDeque<NetworkConnectionRecord>,
    file_op_history: VecDeque<FileOperationRecord>,
    
    baseline: BehaviorBaseline,
}

impl ThreatProfile {
    fn new(pid: Pid, process: &sysinfo::Process, system: &System) -> Self {
        let user_id_str = process.user_id().map(|uid| {
            system.get_user_by_id(uid).map_or_else(
                || format!("UID:{:?}", uid),
                |user| user.name().to_string()
            )
        });

        Self {
            pid,
            name: process.name().to_string(),
            path: process.exe().to_path_buf(),
            cmdline: process.cmd().to_vec(),
            parent: process.parent(),
            user_id: user_id_str,
            indicators: HashSet::new(),
            score: 0,
            current_level: ThreatLevel::Benign,
            last_level_triggered: ThreatLevel::Benign,
            first_seen: Instant::now(),
            cpu_history: VecDeque::with_capacity(CPU_HISTORY_LENGTH),
            network_history: VecDeque::with_capacity(NETWORK_HISTORY_LENGTH),
            file_op_history: VecDeque::with_capacity(MAX_EVENT_HISTORY),
            baseline: BehaviorBaseline::default(),
        }
    }

    fn add_indicator(&mut self, indicator: Indicator) {
        if self.indicators.insert(indicator.clone()) {
            trace!("AI Overlord: PID {} ({}) -> Neuer Indikator: '{}'.", self.pid, self.name, indicator);
            self.recalculate_score();
        }
    }
    
    fn check_for_attack_chains(&mut self, intel_db: &threat_intel::ThreatIntelDB) {
        for chain in &intel_db.attack_chains {
            if chain.stages.iter().all(|stage| self.indicators.contains(stage)) {
                self.add_indicator(Indicator::FollowsMaliciousAttackChain(chain.name.clone()));
            }
        }
    }

    fn recalculate_score(&mut self) {
        let base_score: u32 = self.indicators.iter().map(Indicator::score).sum();
        let mut multiplier = 1.0;

        let from_temp = self.indicators.contains(&Indicator::LaunchedFromTempDir);
        let has_net_activity = self.indicators.iter().any(|i| matches!(i, Indicator::ConnectionToBlacklistedIp(_) | Indicator::NetworkBeaconingDetected));
        let tries_persistence = self.indicators.iter().any(|i| matches!(i, Indicator::RegistryAutorunPersistence(_) | Indicator::ScheduledTaskCreation));

        if from_temp && has_net_activity {
            trace!("AI Overlord: PID {} -> Multiplikator (Temp+Netz) -> *1.5", self.pid);
            multiplier += 0.5;
        }
        if has_net_activity && tries_persistence {
            trace!("AI Overlord: PID {} -> Multiplikator (Netz+Persistenz) -> *1.8", self.pid);
            multiplier += 0.8;
        }
        if self.indicators.contains(&Indicator::MasqueradingAsSystemProcess) && tries_persistence {
             trace!("AI Overlord: PID {} -> Kritischer Multiplikator (Tarnung+Persistenz) -> *2.0", self.pid);
            multiplier += 1.0;
        }
        if self.indicators.contains(&Indicator::CredentialDumpingFromMemory) {
            trace!("AI Overlord: PID {} -> Kritischer Multiplikator (Credential Dumping) -> *2.5", self.pid);
            multiplier += 1.5;
        }

        let attack_chain_count = self.indicators.iter().filter(|i| matches!(i, Indicator::FollowsMaliciousAttackChain(_))).count();
        if attack_chain_count > 0 {
            trace!("AI Overlord: PID {} -> Wende Multiplikator für {} erkannte Angriffskette(n) an.", self.pid, attack_chain_count);
            multiplier += 1.0 * attack_chain_count as f32;
        }

        self.score = (base_score as f32 * multiplier) as u32;
        self.current_level = ThreatLevel::from_score(self.score);
    }
    
    fn decay_score(&mut self) {
        if self.score > 0 {
            let old_score = self.score;
            self.score = (self.score as f32 * SCORE_DECAY_FACTOR).floor() as u32;
            if old_score != self.score {
                trace!("AI Overlord: PID {} -> Score-Verfall: {} -> {}", self.pid, old_score, self.score);
                self.current_level = ThreatLevel::from_score(self.score);
            }
        }
    }

    fn record_file_op(&mut self, path: PathBuf, operation: String) {
        if self.file_op_history.len() >= MAX_EVENT_HISTORY {
            self.file_op_history.pop_front();
        }
        self.file_op_history.push_back(FileOperationRecord {
            timestamp: Instant::now(),
            path,
            operation,
        });
    }
}

struct AiOverlordState {
    tracked_profiles: HashMap<Pid, ThreatProfile>,
    learning_phase_end: Instant,
    threat_intel_db: &'static threat_intel::ThreatIntelDB,
    cycle_count: u64,
    external_event_rx: mpsc::Receiver<ExternalEvent>,
}


pub fn run_ai_overlord(
    app_state: Arc<RwLock<AppState>>,
    shutdown_tx: mpsc::Sender<()>,
    alert_tx: mpsc::Sender<DefenderAlert>,
    settings: Arc<DefenderSettings>,
    external_event_rx: mpsc::Receiver<ExternalEvent>,
) {
    info!("AI Overlord [v7.0 'Leviathan']: Starte strategische Analyse-Engine...");

    let mut system = System::new_all();
    let mut state = AiOverlordState {
        tracked_profiles: HashMap::new(),
        learning_phase_end: Instant::now() + Duration::from_secs(LEARNING_PHASE_SECONDS),
        threat_intel_db: threat_intel::load_db(),
        cycle_count: 0,
        external_event_rx,
    };
    
    warn!("AI Overlord: Lernphase aktiv für {} Sekunden. Multidimensionales Baselining wird durchgeführt.", LEARNING_PHASE_SECONDS);

    loop {
        state.cycle_count += 1;
        let loop_start_time = Instant::now();
        trace!("AI Overlord: Starte Analyse-Zyklus #{}", state.cycle_count);

        let is_learning = Instant::now() < state.learning_phase_end;
        if state.cycle_count % 5 == 0 {
            system.refresh_processes();
        }
        system.refresh_cpu();
        system.refresh_memory();

        ingestion_phase::update_process_roster(&mut system, &mut state);
        ingestion_phase::process_external_events(&mut state);
        
        if is_learning {
            baseliner::perform_learning_step(&mut state, &system);
        } else {
            detector::detect_all_anomalies(&mut state, &system);
        }

        assessment::apply_threat_decay(&mut state);
        assessment::run_correlation_engine(&mut state);
        
        let response_context = response_engine::ResponseContext {
            app_state: &app_state,
            shutdown_tx: &shutdown_tx,
            alert_tx: &alert_tx,
            settings: &settings,
        };
        response_engine::evaluate_and_execute_responses(&mut state, &response_context);

        let elapsed = loop_start_time.elapsed();
        trace!("AI Overlord: Analyse-Zyklus #{} abgeschlossen in {:?}.", state.cycle_count, elapsed);
        if elapsed > ANALYSIS_INTERVAL {
            warn!("AI Overlord: Analyse-Zyklus hat länger gedauert als das Intervall! System unter hoher Last?");
        }
        
        if let Ok(true) = app_state.read().map(|s| s.locked) {
            debug!("AI Overlord: Vault ist gesperrt, pausiere intensive Analyse.");
            thread::sleep(ANALYSIS_INTERVAL * 5);
        } else {
            thread::sleep(ANALYSIS_INTERVAL.saturating_sub(elapsed));
        }
    }
}



mod ingestion_phase {
    use super::*;

    pub fn update_process_roster(system: &mut System, state: &mut AiOverlordState) {
        trace!("Ingestion: Aktualisiere Prozess-Roster...");
        let current_pids: HashSet<_> = system.processes().keys().cloned().collect();
        let tracked_pids: HashSet<_> = state.tracked_profiles.keys().cloned().collect();

        for &pid in current_pids.difference(&tracked_pids) {
            if let Some(process) = system.process(pid) {
                let profile = ThreatProfile::new(pid, process, system);
                trace!("Ingestion: Neuer Prozess entdeckt: '{}' (PID: {})", profile.name, profile.pid);
                state.tracked_profiles.insert(pid, profile);
            }
        }
        
        for &pid in tracked_pids.difference(&current_pids) {
            if let Some(profile) = state.tracked_profiles.remove(&pid) {
                trace!("Ingestion: Prozess '{}' (PID: {}) wurde beendet. Profil wird archiviert.", profile.name, profile.pid);
            }
        }
    }

    pub fn process_external_events(state: &mut AiOverlordState) {
        trace!("Ingestion: Prüfe auf externe Ereignisse...");
        while let Ok(event) = state.external_event_rx.try_recv() {
            match event {
                ExternalEvent::FileAccess { path, process_id, access_type, .. } => {
                    info!("Ingestion: Event 'FileAccess' auf '{}' durch PID {:?}", path.display(), process_id);
                    if let Some(pid_u32) = process_id {
                        let pid = Pid::from_u32(pid_u32);
                        if let Some(profile) = state.tracked_profiles.get_mut(&pid) {
                            debug!("Ingestion: Korreliere Dateizugriff mit '{}' (PID: {})", profile.name, profile.pid);
                            
                            profile.record_file_op(path.clone(), access_type.clone());

                            let critical_files = [VAULT_FILE, CONFIG_FILE];
                            if critical_files.iter().any(|f| path.ends_with(f)) && access_type == "Write" {
                                profile.add_indicator(Indicator::CorrelatedWithCriticalFileWrite(path.to_string_lossy().to_string()));
                            }
                            if state.threat_intel_db.unusual_system_files_to_watch.iter().any(|f| path.ends_with(f)) {
                                profile.add_indicator(Indicator::AccessToUnusualSystemFile(path.to_string_lossy().to_string()));
                            }
                        }
                    }
                }
                ExternalEvent::RegistryAccess { key_path, process_id, .. } => {
                     info!("Ingestion: Event 'RegistryAccess' auf '{}'", key_path);
                    if let Some(pid_u32) = process_id {
                        let pid = Pid::from_u32(pid_u32);
                        if let Some(profile) = state.tracked_profiles.get_mut(&pid) {
                             if state.threat_intel_db.suspicious_registry_keys.iter().any(|k| key_path.starts_with(k)) {
                                profile.add_indicator(Indicator::RegistryAutorunPersistence(key_path));
                             }
                        }
                    }
                }
            }
        }
    }
}

mod baseliner {
    use super::*;

    pub fn perform_learning_step(state: &mut AiOverlordState, system: &System) {
        trace!("Baseliner: Führe Lernschritt für alle Prozesse durch...");
        for profile in state.tracked_profiles.values_mut() {
            if let Some(process) = system.process(profile.pid) {
                learn_cpu_behavior(profile, process);
                learn_file_behavior(profile);
                learn_process_ancestry(profile, system);
            }
        }
    }
    
    fn learn_cpu_behavior(profile: &mut ThreatProfile, process: &sysinfo::Process) {
        let cpu_usage = process.cpu_usage();
        profile.cpu_history.push_back(cpu_usage);
        if profile.cpu_history.len() > CPU_HISTORY_LENGTH {
            profile.cpu_history.pop_front();
        }

        let n = profile.baseline.cpu_baseline.samples + 1;
        let delta = cpu_usage - profile.baseline.cpu_baseline.avg_usage;
        profile.baseline.cpu_baseline.avg_usage += delta / n as f32;
        let delta2 = cpu_usage - profile.baseline.cpu_baseline.avg_usage;
        let m2 = if n > 1 {
            let old_m2 = (profile.baseline.cpu_baseline.std_deviation.powi(2)) * (n - 2) as f32;
            old_m2 + delta * delta2
        } else {
            0.0
        };
        profile.baseline.cpu_baseline.std_deviation = if n > 1 { (m2 / (n-1) as f32).sqrt() } else { 0.0 };
        profile.baseline.cpu_baseline.samples = n;
    }

    fn learn_file_behavior(profile: &mut ThreatProfile) {
        for event in &profile.file_op_history {
            profile.baseline.accessed_file_paths.insert(event.path.clone());
        }
    }
    
    fn learn_process_ancestry(profile: &mut ThreatProfile, system: &System) {
        if let Some(parent_pid) = profile.parent {
            if let Some(parent_process) = system.process(parent_pid) {
                profile.baseline.common_parent_processes.insert(parent_process.name().to_string());
            }
        }
    }
}

mod detector {
    use super::*;
    use super::threat_intel::is_suspicious_parent;

    pub fn detect_all_anomalies(state: &mut AiOverlordState, system: &System) {
        trace!("Detector: Starte Anomalieerkennung für alle Profile.");
        let profiles_to_check: Vec<Pid> = state.tracked_profiles.keys().cloned().collect();
        for pid in profiles_to_check {
             if let Some(profile) = state.tracked_profiles.get_mut(&pid) { 
                detect_process_anomalies(profile, &state.threat_intel_db, system);
                detect_resource_anomalies(profile);
                detect_network_anomalies(profile, &state.threat_intel_db);
                detect_filesystem_anomalies(profile, &state.threat_intel_db);
             }
        }
    }

    fn is_likely_hex_encoded(s: &str) -> bool {
    const MIN_HEX_LEN: usize = 20;
    if s.len() < MIN_HEX_LEN || s.len() % 2 != 0 {
        return false;
    }
    s.chars().all(|c| c.is_ascii_hexdigit())
}

    fn detect_process_anomalies(profile: &mut ThreatProfile, intel: &threat_intel::ThreatIntelDB, system: &System) {
        if intel.suspicious_process_names.contains(profile.name.to_lowercase().as_str()) {
            profile.add_indicator(Indicator::NameInThreatIntel);
        }

        let temp_dirs = [env::temp_dir(), PathBuf::from("C:\\Windows\\Temp")];
        if temp_dirs.iter().any(|p| profile.path.starts_with(p)) {
            profile.add_indicator(Indicator::LaunchedFromTempDir);
        }
        
        let lower_name = profile.name.to_lowercase();
        if (lower_name == "svchost.exe" && !profile.path.starts_with("C:\\Windows\\System32")) ||
           (lower_name == "lsass.exe" && !profile.path.starts_with("C:\\Windows\\System32")) {
            profile.add_indicator(Indicator::MasqueradingAsSystemProcess);
        }

        if let Some(parent_pid) = profile.parent {
            if let Some(parent) = system.process(parent_pid) {
                if is_suspicious_parent(parent.name()) {
                    profile.add_indicator(Indicator::ParentProcessIsUnusual(parent.name().to_string()));
                }
            } else {
                 profile.add_indicator(Indicator::ProcessIsOrphaned);
            }
        } else {
            profile.add_indicator(Indicator::ProcessIsOrphaned);
        }
        
let mut new_cmdline_indicators: Vec<Indicator> = Vec::new();
        for arg in &profile.cmdline {
            if intel.suspicious_cmd_args.iter().any(|s| arg.contains(s)) {
                new_cmdline_indicators.push(Indicator::CmdlineContainsSuspiciousArgs(arg.clone()));
            }
            if let Ok(decoded) = STANDARD.decode(arg) {
                if String::from_utf8_lossy(&decoded).contains("powershell") {
                    new_cmdline_indicators.push(Indicator::CmdlineObfuscated("Base64".to_string()));
                }
            }
            if is_likely_hex_encoded(arg) {
                if hex::decode(arg).is_ok() {
                     new_cmdline_indicators.push(Indicator::CmdlineObfuscated("Hex".to_string()));
                }
            }
        }
        for indicator in new_cmdline_indicators {
            profile.add_indicator(indicator);
        }
    }
    

    fn detect_resource_anomalies(profile: &mut ThreatProfile) {
        if let Some(&current_cpu) = profile.cpu_history.back() {
            let baseline = &profile.baseline.cpu_baseline;
            if baseline.samples > 10 && baseline.std_deviation > 0.1 && current_cpu > (baseline.avg_usage + CPU_DEVIATION_SIGMA * baseline.std_deviation) {
                profile.add_indicator(Indicator::AnomalousCpuSpike);
            }
            if current_cpu > HIGH_CPU_THRESHOLD {
                 profile.add_indicator(Indicator::SustainedHighCpuUsage);
            }
        }
    }

    fn detect_network_anomalies(profile: &mut ThreatProfile, intel: &threat_intel::ThreatIntelDB) {
        let new_connections: Vec<NetworkConnectionRecord> = Vec::new();

        for conn in new_connections {
             if intel.blacklisted_ips.contains(&conn.remote_ip.to_string()) {
                profile.add_indicator(Indicator::ConnectionToBlacklistedIp(conn.remote_ip.to_string()));
            }
            if !profile.baseline.known_remote_ips.contains(&conn.remote_ip) {
                profile.add_indicator(Indicator::ConnectionToNewIp);
            }
        }
        
        if profile.network_history.len() > MIN_BEACONING_COUNT {
            let timestamps: Vec<_> = profile.network_history.iter().map(|r| r.timestamp).collect();
            let intervals: Vec<_> = timestamps.windows(2).map(|w| w[1] - w[0]).collect();
            if let Some(first_interval) = intervals.first() {
                if intervals.iter().all(|&i| (i.as_secs_f64() - first_interval.as_secs_f64()).abs() < BEACONING_INTERVAL_TOLERANCE.as_secs_f64()) {
                    profile.add_indicator(Indicator::NetworkBeaconingDetected);
                }
            }
        }
    }
    
    fn detect_filesystem_anomalies(profile: &mut ThreatProfile, intel: &threat_intel::ThreatIntelDB) {
        let mut indicators_to_add: Vec<Indicator> = Vec::new();
        let mut exe_in_temp_count = 0;
        let mut mass_delete_count = 0;

        for op in &profile.file_op_history {
            if intel.browser_db_paths.iter().any(|p| op.path.ends_with(p)) {
                 indicators_to_add.push(Indicator::ModificationOfBrowserDatabases);
            }
            
            if op.operation == "Create" && op.path.extension().map_or(false, |e| e == "exe" || e == "dll") {
                let temp_dirs = [env::temp_dir(), PathBuf::from("C:\\Windows\\Temp")];
                if temp_dirs.iter().any(|p| op.path.starts_with(p)) {
                   exe_in_temp_count += 1;
                }
            }

            if op.operation == "Delete" {
                mass_delete_count += 1;
            }
        }
        
        if exe_in_temp_count > 0 {
            indicators_to_add.push(Indicator::CreatesExecutableInTemp);
        }
        if mass_delete_count > 50 {
             indicators_to_add.push(Indicator::MassFileRenamingOrDeletion);
        }

        for indicator in indicators_to_add {
            profile.add_indicator(indicator);
        }
    }
}

mod assessment {
    use super::*;

    pub fn apply_threat_decay(state: &mut AiOverlordState) {
        trace!("Assessment: Wende Score-Verfall an.");
        for profile in state.tracked_profiles.values_mut() {
            profile.decay_score();
        }
    }
    
    pub fn run_correlation_engine(state: &mut AiOverlordState) {
        trace!("Assessment: Starte Korrelations-Engine.");
        let pids: Vec<Pid> = state.tracked_profiles.keys().cloned().collect();
        for pid in pids {
            if let Some(profile) = state.tracked_profiles.get_mut(&pid) { 
                profile.check_for_attack_chains(&state.threat_intel_db);
            }
        }
    }
}

mod response_engine {
    use super::*;

    pub struct ResponseContext<'a> {
        pub app_state: &'a Arc<RwLock<AppState>>,
        pub shutdown_tx: &'a mpsc::Sender<()>,
        pub alert_tx: &'a mpsc::Sender<DefenderAlert>, // HIER IST EIN FEHLER: Muss mpsc::Sender sein, nicht mpsc - Korrigiert!
        pub settings: &'a Arc<DefenderSettings>,
    }

    pub fn evaluate_and_execute_responses(state: &mut AiOverlordState, context: &ResponseContext) {
        trace!("Response Engine: Evaluiere Bedrohungen und reagiere.");
        for profile in state.tracked_profiles.values_mut() {
            if profile.current_level > profile.last_level_triggered {
                warn!(
                    "AI Overlord: Eskalation für PID {} ({}). Level: {:?} -> {:?} (Score: {})",
                    profile.pid, profile.name, profile.last_level_triggered, profile.current_level, profile.score
                );

                let reasons: Vec<String> = profile.indicators.iter().map(|i| i.to_string()).collect();

                let alert = DefenderAlert {
                    reason: DefenderAlertReason::AiThreatEscalation {
                        process_name: profile.name.clone(),
                        pid: profile.pid.as_u32(),
                        score: profile.score,
                        detected_indicators: reasons,
                    },
                    suggested_action_level: map_threat_to_action(profile.current_level),
                };

                 if let Err(e) = context.alert_tx.send(alert) {
                     error!("AI Overlord (Response): Konnte Alert nicht an Haupt-Thread senden: {}", e);
                 }


                match profile.current_level {
                    ThreatLevel::HighRisk => {
                        info!("Response Engine: Löse Guardian Full Re-Scan aus aufgrund von HighRisk.");
                        let guardian_tx = context.alert_tx.clone();
                        let guardian_settings = context.settings.clone();
                        thread::spawn(move || {
                            guardian::initialize_defender_massively(guardian_settings, guardian_tx)
                                .unwrap_or_else(|e| {
                                    error!("Fehler beim Auslösen des Guardian Re-Scan: {}", e);
                                    None
                                });
                        });
                    }
                    ThreatLevel::Imminent => {
                        info!("Response Engine: Autonome Sperrung des Vaults wird eingeleitet.");
                        if let Ok(mut app_state) = context.app_state.write() {
                            app_state.locked = true;
                            if let Some(mut key) = app_state.key.take() {
                                key.zeroize();
                                info!("Vault-Schlüssel im Speicher aufgrund von Bedrohung genullt.");
                            }
                        }
                    }
                    ThreatLevel::Compromised => {
                        warn!("Response Engine: System kompromittiert! Notabschaltung wird eingeleitet.");
                        if let Err(e) = context.shutdown_tx.send(()) {
                            error!("Konnte Notabschaltung nicht signalisieren: {}", e);
                        }
                    }
                    _ => {}
                }
                profile.last_level_triggered = profile.current_level;
            }
        }
    }

    fn map_threat_to_action(level: ThreatLevel) -> DefenderActionLevel {
        match level {
            ThreatLevel::Benign | ThreatLevel::Informational => DefenderActionLevel::LogOnly,
            ThreatLevel::Suspicious => DefenderActionLevel::WarnUser,
            ThreatLevel::HighRisk => DefenderActionLevel::WarnUserCritical,
            ThreatLevel::Imminent => DefenderActionLevel::LockVault,
            ThreatLevel::Compromised => DefenderActionLevel::Shutdown,
        }
    }
}


mod threat_intel {
    use super::{HashSet, Indicator};
    use lazy_static::lazy_static;

    pub struct AttackChain {
        pub name: String,
        pub description: String,
        pub stages: Vec<Indicator>,
    }

    pub struct ThreatIntelDB {
        pub suspicious_process_names: HashSet<&'static str>,
        pub suspicious_parent_processes: HashSet<&'static str>,
        pub suspicious_cmd_args: HashSet<&'static str>,
        pub blacklisted_ips: HashSet<String>,
        pub suspicious_domains: HashSet<String>,
        pub unusual_system_files_to_watch: HashSet<&'static str>,
        pub browser_db_paths: HashSet<&'static str>,
        pub suspicious_registry_keys: HashSet<&'static str>,
        pub attack_chains: Vec<AttackChain>,
    }

    lazy_static! {
        static ref THREAT_INTEL_DB: ThreatIntelDB = ThreatIntelDB {
            suspicious_process_names: [
                "mimikatz.exe", "powersploit.exe", "bloodhound.exe", "procdump.exe",
                "nc.exe", "ncat.exe", "plink.exe", "koadic.py", "cain.exe",
                "wireshark.exe", "fiddler.exe", "x64dbg.exe", "ollydbg.exe",
            ].iter().cloned().collect(),
            suspicious_parent_processes: [
                "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                "wscript.exe", "cscript.exe", "mshta.exe", "wmiprvse.exe"
            ].iter().cloned().collect(),
            suspicious_cmd_args: [
                "-enc", "-encodedcommand", "-executionpolicy", "bypass",
                "iwr", "invoke-webrequest", "invoke-expression", "iex",
                "shadowcopy", "vssadmin", "delete shadows"
            ].iter().cloned().collect(),
            blacklisted_ips: HashSet::new(),
            suspicious_domains: [
                ".xyz", ".top", ".club", ".ddns.net", ".duckdns.org"
            ].iter().map(|s| s.to_string()).collect(),
            unusual_system_files_to_watch: [
                "sam", "system", "security",
                "/etc/shadow", "/etc/passwd"
            ].iter().cloned().collect(),
            browser_db_paths: [
                "Login Data", "Web Data", "Cookies",
                "places.sqlite", "key4.db", "cookies.sqlite"
            ].iter().cloned().collect(),
            suspicious_registry_keys: [
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
            ].iter().cloned().collect(),
            attack_chains: vec![
                AttackChain {
                    name: "Living-off-the-Land: PowerShell Download & Exec".to_string(),
                    description: "Ein Office-Dokument startet PowerShell, um ein Skript nachzuladen und auszuführen.".to_string(),
                    stages: vec![
                        Indicator::ParentProcessIsUnusual("winword.exe".to_string()),
                        Indicator::NameInThreatIntel,
                        Indicator::CmdlineContainsSuspiciousArgs("iwr".to_string()),
                        Indicator::CmdlineContainsSuspiciousArgs("iex".to_string()),
                    ],
                },
                AttackChain {
                    name: "Fileless Persistence via WMI".to_string(),
                    description: "Ein Angreifer nutzt WMI, um persistenten, dateilosen Code auszuführen.".to_string(),
                    stages: vec![
                        Indicator::ParentProcessIsUnusual("wmiprvse.exe".to_string()),
                        Indicator::WmiPersistenceEventTrigger,
                        Indicator::CmdlineObfuscated("Base64".to_string()),
                        Indicator::NetworkBeaconingDetected,
                    ]
                }
            ],
        };
    }

    pub fn load_db() -> &'static ThreatIntelDB {
        &THREAT_INTEL_DB
    }

    pub fn is_suspicious_parent(name: &str) -> bool {
        THREAT_INTEL_DB.suspicious_parent_processes.contains(name.to_lowercase().as_str())
    }
}