
use std::io;
use thiserror::Error;
use rust_i18n::t;
use std::cmp::PartialOrd;
use std::cmp::PartialEq;
use std::path::PathBuf;


#[derive(Error, Debug)]
pub enum VaultError {
    #[error("{}", t!("errors.io_error", details = _0.to_string()))]
    Io(#[from] io::Error),

    #[error("{}", t!("errors.serialization_error", details = _0.to_string()))]
    Serialization(#[from] serde_json::Error),

    #[error("{}", t!("errors.deserialization_error", details = _0.to_string()))]
    Deserialization(serde_json::Error),

    #[error("{}", t!("errors.encryption_error", details = _0.to_string()))]
    Encryption(aes_gcm::Error),

    #[error("{}", t!("errors.config_error", details = _0))]
    ConfigError(String),

    #[error("{}", t!("errors.invalid_data_error", details = _0))]
    InvalidData(String),

    #[error("{}", t!("errors.hex_decode_error", details = _0.to_string()))]
    HexDecode(#[from] hex::FromHexError),

    #[error("{}", t!("errors.base64_decode_error", details = _0.to_string()))]
    Base64Decode(#[from] base64::DecodeError),

    #[error("{}", t!("errors.vault_lock_failed", details = _0))]
    VaultLockError(String),

    #[error("{}", t!("errors.clipboard_error", details = _0))]
    ClipboardError(String),

    #[allow(dead_code)]
    #[error("{}", t!("errors.clipboard_timeout", details = _0))]
    ClipboardTimeout(String),

    #[allow(dead_code)]
    #[error("{}", t!("errors.prompt_cancelled", details = _0))]
    PromptCancelled(String),

    #[error("{}", t!("errors.password_or_keyfile_verification_failed"))]
    PasswordOrKeyfileVerification,


    #[error("{}", t!("errors.vault_file_not_found", path = _0))]
    VaultFileNotFound(String),

    #[allow(dead_code)]
    #[error("{}", t!("errors.config_file_not_found", path = _0))]
    ConfigFileNotFound(String),

     #[error("{}", t!("errors.import_file_not_found", path = _0))]
     ImportFileNotFound(String),

    #[error("{}", t!("errors.import_path_not_file", path = _0))]
    ImportPathNotFile(String),

     #[allow(dead_code)]
     #[error("{}", t!("errors.unsupported_operation", details = _0))]
     UnsupportedOperation(String),

    #[error("{}", t!("errors.csv_export_error", details = _0.to_string()))]
    CsvExportError(#[from] csv::Error),

    #[error("{}", t!("errors.invalid_vault_format", details = _0))]
    InvalidVaultFormat(String),

    #[error("{}", t!("errors.password_read_failed", details = _0.to_string()))]
    PasswordReadFailed(io::Error),

    #[error("{}", t!("errors.zxcvbn_error", details = _0))]
    ZxcvbnError(String),

    #[error("{}", t!("errors.keyfile_error", details = _0))]
    KeyfileError(String),

    #[error("{}", t!("errors.argon2_error_details", details = _0))]
    Argon2Error(String),
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DefenderActionLevel {
    LogOnly,
    WarnUser,
    WarnUserCritical,
    LockVault,
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum DefenderAlertReason {
    DebuggerDetected(String),
    VMDetected(String),
    SuspiciousProcessFound(String, Vec<String>),
    ParentProcessSuspicious(String, String),

    ExecutableHashMismatch { executable_path: String, expected_hash: String, calculated_hash: String },
    RuntimeCriticalFunctionTampered { function_address: String, original_bytes_preview: String, current_bytes_preview: String },
    
    SuspiciousEnvironmentVariable(String, String),
    UnusualMemoryRegion(String),
    LinuxPtraceAttached(i32),
    PebBeingDebuggedFlagDetected,
    NtGlobalFlagDebuggedDetected,
    CriticalFileModified(PathBuf, String), 
    HoneypotTriggered(PathBuf, String),
    
    AiThreatEscalation {
        process_name: String,
        pid: u32,
        score: u32,
        detected_indicators: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct DefenderAlert {
    pub reason: DefenderAlertReason,
    pub suggested_action_level: DefenderActionLevel,
}