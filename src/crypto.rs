use crate::config::{self, KEY_SIZE, NONCE_SIZE};
use crate::errors::VaultError;
use crate::models::EncryptionKey;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{self, Algorithm, Argon2, Params, Version};
use rand::{
    RngCore,
};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};
use zeroize::Zeroizing;
use rust_i18n::t;
use::rand::Rng;
use std::io::Write;       
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt; 

pub const DEFAULT_KEYFILE_SIZE_BYTES: usize = 64;
pub const DEFAULT_PASSWORD_SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?";

#[derive(Debug)]
pub struct PasswordOptions {
    pub length: usize,
    pub use_lowercase: bool,
    pub use_uppercase: bool,
    pub use_digits: bool,
    pub use_symbols: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        PasswordOptions {
            length: 16,
            use_lowercase: true,
            use_uppercase: true,
            use_digits: true,
            use_symbols: true,
        }
    }
}


pub fn read_keyfile_securely(path: &Path) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    log::debug!("Lese Keyfile: {}", path.display());

    config::check_keyfile_permissions(path);

    if !path.exists() {
        log::error!("Keyfile nicht gefunden: {}", path.display());
        return Err(VaultError::KeyfileError(t!("errors.keyfile_not_found_path", path=path.display().to_string())));
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 {
        log::error!("Keyfile ist leer: {}", path.display());
        return Err(VaultError::KeyfileError(t!("errors.keyfile_empty", path=path.display().to_string())));
    }
    if metadata.len() > 1024 * 1024 {
        log::error!("Keyfile ist zu groß (> 1MB): {}", path.display());
        return Err(VaultError::KeyfileError(t!("errors.keyfile_too_large", path=path.display().to_string())));
    }

    let mut keyfile_content = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    keyfile_content.resize(metadata.len() as usize, 0);

    let mut file = File::open(path)?;
    file.read_exact(&mut keyfile_content)?;
    log::info!(
        "Keyfile erfolgreich gelesen ({} bytes).",
        keyfile_content.len()
    );
    Ok(keyfile_content)
}

#[allow(dead_code)]
pub fn derive_key_from_inputs(
    password: &Zeroizing<String>,
    keyfile_content: Option<&Zeroizing<Vec<u8>>>,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<EncryptionKey, VaultError> {
    log::debug!(
        "Leite Schlüssel ab mit Argon2id (m={}, t={}, p={}, keyfile={})",
        m_cost,
        t_cost,
        p_cost,
        keyfile_content.is_some()
    );
    let mut key_bytes = Zeroizing::new([0u8; KEY_SIZE]);

    let mut combined_input = Zeroizing::new(Vec::new());
    combined_input.extend_from_slice(password.as_bytes());
    if let Some(kf_content) = keyfile_content {
        combined_input.extend_from_slice(kf_content);
    }

    if m_cost == 0 || t_cost == 0 || p_cost == 0 {
        log::error!("Ungültige Argon2 Parameter für Ableitung: m={}, t={}, p={}", m_cost, t_cost, p_cost);
        return Err(VaultError::Argon2Error(t!("errors.argon2_invalid_params_runtime")));
    }

    let params = Params::new(m_cost, t_cost, p_cost, Some(KEY_SIZE)).map_err(|e| {
        log::error!("Ungültige Argon2 Parameter erstellt: {}", e);
        VaultError::Argon2Error(t!("errors.argon2_invalid_params", details = e.to_string()))
    })?;
    log::trace!("Argon2 Parameter erstellt: {:?}", params);

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    log::trace!("Starte Argon2 Hashing...");
    argon2
        .hash_password_into(&combined_input, salt, &mut *key_bytes)
        .map_err(|e| {
            log::error!("Argon2 Fehler: {}", e);
            VaultError::Argon2Error(t!("errors.argon2_hashing_failed", details = e.to_string()))
        })?;
    log::debug!("Argon2 Hashing abgeschlossen.");

    let key = Key::<Aes256Gcm>::clone_from_slice(&*key_bytes);
    log::info!("AES-GCM Schlüssel erfolgreich abgeleitet.");
    Ok(EncryptionKey(key))
}


pub fn generate_password_custom(
    options: &PasswordOptions,
    custom_symbols: Option<&str>
) -> Result<String, VaultError> {
    let mut charset = Vec::new();
    if options.use_lowercase {
        charset.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz");
    }
    if options.use_uppercase {
        charset.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if options.use_digits {
        charset.extend_from_slice(b"0123456789");
    }

    let symbols_to_use: &[u8] = custom_symbols
        .filter(|s| !s.is_empty())
        .map(|s| s.as_bytes())
        .unwrap_or(DEFAULT_PASSWORD_SYMBOLS);

    if options.use_symbols {
        charset.extend_from_slice(symbols_to_use);
    }

    if charset.is_empty() {
         return Err(VaultError::InvalidData(t!("errors.password_gen_no_charset")));
    }
    if options.length == 0 {
        return Err(VaultError::InvalidData(t!("errors.password_gen_zero_length")));
    }

    let mut rng = rand::thread_rng();
    let password: String = (0..options.length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect();

    Ok(password)
}


pub fn encrypt_data(
    key: &EncryptionKey,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
    log::debug!("Verschlüssele Daten ({} bytes)...", plaintext.len());
    let cipher = Aes256Gcm::new(&key.0);
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    log::trace!("Nonce generiert: {}", hex::encode(nonce_bytes));

    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
        log::error!("AES Verschlüsselungsfehler: {}", e);
        VaultError::Encryption(e)
    })?;
    log::debug!(
        "Verschlüsselung erfolgreich (Ciphertext: {} bytes).",
        ciphertext.len()
    );
    Ok((nonce_bytes.to_vec(), ciphertext))
}

pub fn decrypt_data(
    key: &EncryptionKey,
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    log::debug!(
        "Entschlüssele Daten (Ciphertext: {} bytes)...",
        ciphertext.len()
    );
    if nonce_bytes.len() != NONCE_SIZE {
        log::error!("Ungültige Nonce Länge: {}", nonce_bytes.len());
        return Err(VaultError::InvalidData(t!("errors.invalid_nonce_length", expected = NONCE_SIZE, got = nonce_bytes.len())));
    }
    let cipher = Aes256Gcm::new(&key.0);
    let nonce = Nonce::from_slice(nonce_bytes);
    log::trace!("Verwende Nonce: {}", hex::encode(nonce_bytes));

    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        log::warn!(
            "AES Entschlüsselungsfehler (potenziell falsches PW/Keyfile/korrupte Daten): {}",
            e
        );
        VaultError::PasswordOrKeyfileVerification
    })
}

pub fn generate_and_save_keyfile(path: &Path, size_bytes: usize) -> Result<(), VaultError> {
    log::info!("Generiere neues Keyfile unter Pfad: {} ({} Bytes)", path.display(), size_bytes);

    if path.exists() && !path.is_dir() {
        log::debug!("Keyfile '{}' existiert und wird überschrieben (Annahme: Bestätigung durch CLI erfolgt).", path.display());
    }


    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| {
                log::error!("Konnte Elternverzeichnis '{}' für Keyfile nicht erstellen: {}", parent.display(), e);
                VaultError::Io(e)
            })?;
            log::debug!("Elternverzeichnis für Keyfile erstellt: {}", parent.display());
        }
    }

    let mut key_data = vec![0u8; size_bytes];
    aes_gcm::aead::OsRng.fill_bytes(&mut key_data);
    log::debug!("{} zufällige Bytes für Keyfile generiert.", size_bytes);

    let mut file = File::create(path).map_err(|e| {
        log::error!("Fehler beim Erstellen der Keyfile-Datei '{}': {}", path.display(), e);
        VaultError::Io(e)
    })?;

    #[cfg(unix)]
    {
        if let Ok(metadata) = file.metadata() {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            if let Err(e) = file.set_permissions(permissions) {
                 log::warn!(
                    "Konnte initiale Berechtigungen (0o600) für Keyfile '{}' nicht setzen: {}. Versuche es nach dem Schreiben erneut.",
                    path.display(), e
                );
            } else {
                log::debug!("Initiale Berechtigungen für Keyfile '{}' auf 0o600 gesetzt.", path.display());
            }
        } else {
            log::warn!("Konnte Metadaten für neu erstelltes Keyfile '{}' nicht sofort abrufen.", path.display());
        }
    }

    file.write_all(&key_data).map_err(|e| {
        log::error!("Fehler beim Schreiben der Daten in Keyfile-Datei '{}': {}", path.display(), e);
        VaultError::Io(e)
    })?;
    file.sync_all().map_err(VaultError::Io)?;
    drop(file);

    log::info!("Keyfile erfolgreich in '{}' gespeichert.", path.display());

    #[cfg(unix)]
    {
        match fs::metadata(path) {
            Ok(metadata) => {
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o400);
                if let Err(e) = fs::set_permissions(path, permissions) {
                    log::warn!(
                        "Konnte endgültige Berechtigungen (0o400) für Keyfile '{}' nicht setzen: {}",
                        path.display(), e
                    );
                } else {
                    log::debug!("Endgültige Berechtigungen für Keyfile '{}' auf 0o400 gesetzt.", path.display());
                }
            }
            Err(e) => log::warn!("Konnte Metadaten für Keyfile '{}' nicht lesen, um endgültige Berechtigungen zu setzen: {}", path.display(), e),
        }
    }
    #[cfg(windows)]
    {
        config::check_keyfile_permissions(path);
    }

    Ok(())
}