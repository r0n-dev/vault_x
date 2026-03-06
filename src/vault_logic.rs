use std::fs;
use crate::config::{
    VaultConfig, VAULT_FILE, NONCE_SIZE, SALT_SIZE,
    ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST, KEY_SIZE,
};
use crate::crypto::{
    decrypt_data, encrypt_data, read_keyfile_securely,
};
use crate::errors::VaultError;
use crate::models::{AppState, EncryptedExportData, EncryptionKey, Vault};
use aes_gcm::aead::OsRng;
use argon2::{self, Algorithm, Argon2, Params, Version};
use rand::RngCore;
use std::{
    fs::{File},
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};
use zeroize::Zeroizing;
use rust_i18n::t;
use csv::WriterBuilder;
use aes_gcm::Aes256Gcm;

fn derive_key_from_inputs_with_params(
    master_password: &Zeroizing<String>,
    salt: &[u8],
    keyfile_content: Option<&[u8]>,
    params_opt: Option<Params>,
) -> Result<EncryptionKey, VaultError> {
    log::debug!(
        "Leite Schlüssel ab mit Argon2id (keyfile={}), spezifische/default Params.",
        keyfile_content.is_some()
    );

    let params = params_opt.unwrap_or_else(|| {
        Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_SIZE))
            .expect("Fehler beim Erstellen der Standard Argon2 Parameter")
    });
    log::trace!("Argon2 Parameter für Ableitung: {:?}", params);

    let mut combined_secret = Zeroizing::new(Vec::new());
    combined_secret.extend_from_slice(master_password.as_bytes());
    if let Some(kf_data) = keyfile_content {
        combined_secret.extend_from_slice(kf_data);
    }

    let mut key_bytes = Zeroizing::new([0u8; KEY_SIZE]);

    let argon2_instance = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    );

    match argon2_instance.hash_password_into(&combined_secret, salt, &mut *key_bytes) {
        Ok(_) => {
            let key_value = aes_gcm::Key::<Aes256Gcm>::clone_from_slice(&*key_bytes);
            log::info!("AES-GCM Schlüssel erfolgreich abgeleitet.");
            Ok(EncryptionKey(key_value))
        }
        Err(e) => {
            log::error!("Argon2 Fehler bei Schlüsselableitung: {}", e);
            Err(VaultError::PasswordOrKeyfileVerification)
        }
    }
}

fn derive_key_from_inputs_with_defaults(
    master_password: &Zeroizing<String>,
    salt: &[u8],
    keyfile_content: Option<&[u8]>,
) -> Result<EncryptionKey, VaultError> {
    let default_params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_SIZE))
        .map_err(|e| VaultError::Argon2Error(format!("Fehler beim Erstellen der Standard Argon2 Parameter: {}", e)))?;
    derive_key_from_inputs_with_params(master_password, salt, keyfile_content, Some(default_params))
}


pub fn save_vault(vault: &Vault, key: &EncryptionKey) -> Result<(), VaultError> {
    log::debug!("Speichere Vault nach '{}'...", VAULT_FILE);
    let vault_path = PathBuf::from(VAULT_FILE);
    let vault_json = serde_json::to_string(vault).map_err(|e| {
        log::error!("Fehler beim Serialisieren des Vaults: {}", e);
        VaultError::Serialization(e)
    })?;
    log::trace!(
        "Vault JSON (Plaintext, Länge {}) für Verschlüsselung serialisiert.",
        vault_json.len()
    );

    let plaintext_bytes = vault_json.into_bytes();
    let (nonce_bytes, ciphertext) = encrypt_data(key, &plaintext_bytes)?;

    let mut file = File::create(&vault_path).map_err(|e| {
        log::error!("Fehler beim Erstellen der Vault-Datei '{}': {}", vault_path.display(), e);
        VaultError::Io(e)
    })?;

    file.write_all(&nonce_bytes).map_err(|e| {
        log::error!("Fehler beim Schreiben der Nonce in Vault-Datei '{}': {}", vault_path.display(), e);
        VaultError::Io(e)
    })?;
     file.write_all(&ciphertext).map_err(|e| {
        log::error!("Fehler beim Schreiben des Ciphertexts in Vault-Datei '{}': {}", vault_path.display(), e);
        VaultError::Io(e)
    })?;


    log::debug!("Vault erfolgreich in '{}' gespeichert.", vault_path.display());
    Ok(())
}

pub fn load_vault(key: &EncryptionKey) -> Result<Vault, VaultError> {
    log::debug!("Lade Vault aus '{}'...", VAULT_FILE);
    let vault_path = PathBuf::from(VAULT_FILE);

    if !vault_path.exists() {
        log::warn!("Vault-Datei '{}' nicht gefunden.", vault_path.display());
        return Err(VaultError::VaultFileNotFound(vault_path.display().to_string()));
    }

    let mut file = File::open(&vault_path).map_err(|e| {
        log::error!("Fehler beim Öffnen der Vault-Datei '{}': {}", vault_path.display(), e);
        VaultError::Io(e)
    })?;

    let mut nonce_bytes = vec![0u8; NONCE_SIZE];
    if file.read_exact(&mut nonce_bytes).is_err() {
        log::error!("Vault-Datei '{}' ist zu klein oder beschädigt (keine vollständige Nonce).", vault_path.display());
         return Err(VaultError::InvalidVaultFormat(t!("errors.vault_file_too_small", path = vault_path.display())));
    }

    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext).map_err(|e| {
        log::error!("Fehler beim Lesen des Ciphertexts aus Vault-Datei '{}': {}", vault_path.display(), e);
        VaultError::Io(e)
    })?;

    log::trace!("Nonce gelesen ({} bytes), Ciphertext gelesen ({} bytes).", nonce_bytes.len(), ciphertext.len());

    let plaintext_bytes = decrypt_data(key, &nonce_bytes, &ciphertext)?;


    log::trace!("Daten erfolgreich entschlüsselt ({} bytes).", plaintext_bytes.len());

    let vault: Vault = serde_json::from_slice(&plaintext_bytes).map_err(|e| {
        log::error!("Fehler beim Deserialisieren des Vaults: {}", e);
        VaultError::Deserialization(e)
    })?;

    log::debug!("Vault erfolgreich geladen und deserialisiert.");
    Ok(vault)
}

pub fn initialize_new_vault_from_config(
    master_password: Zeroizing<String>,
    config: &VaultConfig,
) -> Result<AppState, VaultError> {
    log::info!("Initialisiere neuen Vault basierend auf existierender neuer Konfiguration.");
    let new_vault = Vault::default();

    let salt_bytes = match hex::decode(&config.salt_hex) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Ungültiges Salt-Format in neuer Konfiguration beim Initialisieren: {}", e);
            return Err(VaultError::ConfigError(format!(
                "Ungültiges Salt-Format ('{}') in neuer Konfiguration: {}",
                config.salt_hex, e
            )));
        }
    };

    if salt_bytes.is_empty() {
        log::error!("Salt aus neuer Konfiguration ist leer.");
        return Err(VaultError::ConfigError(
            "Salt aus neuer Konfiguration darf nicht leer sein.".to_string(),
        ));
    }

    log::debug!(
        "Verwende Salt aus neuer Konfiguration und Argon2-Parameter (m={}, t={}, p={}) für initialen Schlüssel.",
        config.m_cost, config.t_cost, config.p_cost
    );

    let argon2_params = match Params::new(config.m_cost, config.t_cost, config.p_cost, Some(KEY_SIZE)) {
        Ok(p) => p,
        Err(e) => {
            log::error!("Ungültige Argon2 Parameter aus neuer Konfiguration beim Initialisieren: {}", e);
            return Err(VaultError::ConfigError(format!(
                "Ungültige Argon2 Parameter (m={}, t={}, p={}) in neuer Konfiguration: {}",
                config.m_cost, config.t_cost, config.p_cost, e
            )));
        }
    };

    let keyfile_content_owned: Option<Zeroizing<Vec<u8>>> =
        if let Some(kf_path_str) = &config.keyfile_path {
            let kf_path = Path::new(kf_path_str);
            log::debug!("Lese Keyfile '{}' für initiale Schlüsselerzeugung des neuen Vaults.", kf_path.display());
            match read_keyfile_securely(kf_path) {
                Ok(content) => {
                    log::info!("Keyfile '{}' erfolgreich für initialen Schlüssel gelesen.", kf_path.display());
                    Some(content)
                }
                Err(e) => {
                    log::error!(
                        "Kritischer Fehler: Keyfile '{}' ist konfiguriert, konnte aber für die initiale Schlüsselerzeugung nicht gelesen werden: {}",
                        kf_path.display(),
                        e
                    );
                    return Err(e);
                }
            }
        } else {
            log::debug!("Kein Keyfile konfiguriert für initiale Schlüsselerzeugung.");
            None
        };

    let key = match derive_key_from_inputs_with_params(
        &master_password,
        &salt_bytes,
        keyfile_content_owned.as_ref().map(|z_vec| z_vec.as_slice()),
        Some(argon2_params),
    ) {
        Ok(k) => k,
        Err(e) => {
            log::error!("Fehler bei initialer Schlüsselableitung basierend auf Config: {}", e);
            return Err(e);
        }
    };
    log::debug!("Initialer Schlüssel basierend auf Konfiguration abgeleitet.");

    Ok(AppState {
        vault: new_vault,
        key: Some(key),
        last_activity: Instant::now(),
        locked: false,
    })
}


pub fn unlock_and_load_vault(config: &VaultConfig, master_password: Zeroizing<String>) -> Result<AppState, VaultError> {
    log::info!("Versuche Vault zu entschlüsseln und zu laden.");

    let salt = hex::decode(&config.salt_hex).map_err(VaultError::HexDecode)?;

    let keyfile_content_owned: Option<Zeroizing<Vec<u8>>> = if let Some(kf_path_str) = &config.keyfile_path {
        let kf_path = Path::new(kf_path_str);
        log::debug!("Lese Keyfile von: {}", kf_path.display());
         match read_keyfile_securely(kf_path) {
             Ok(content) => {
                 log::debug!("Keyfile erfolgreich gelesen ({} bytes).", content.len());
                 Some(content)
             }
             Err(e) => {
                 log::error!("Fehler beim Lesen des Keyfiles '{}': {}", kf_path.display(), e);
                 return Err(e);
             }
         }
    } else {
        log::debug!("Kein Keyfile konfiguriert.");
        None
    };

    log::debug!(
        "Leite Schlüssel mit Argon2 (m={}, t={}, p={}) ab...",
        config.m_cost, config.t_cost, config.p_cost
    );
    let argon2_params = match Params::new(config.m_cost, config.t_cost, config.p_cost, Some(KEY_SIZE)) {
        Ok(p) => p,
        Err(e) => {
            log::error!("Ungültige Argon2 Parameter aus Konfiguration beim Entsperren: {}", e);
            return Err(VaultError::ConfigError(format!(
                "Ungültige Argon2 Parameter (m={}, t={}, p={}) in Konfiguration: {}",
                config.m_cost, config.t_cost, config.p_cost, e
            )));
        }
    };

    let derived_key = match derive_key_from_inputs_with_params(
        &master_password,
        &salt,
        keyfile_content_owned.as_ref().map(|z| z.as_ref()),
        Some(argon2_params)
    ) {
        Ok(key) => key,
        Err(VaultError::PasswordOrKeyfileVerification) => {
            log::warn!("{}", t!("log.password_or_keyfile_incorrect"));
            return Err(VaultError::PasswordOrKeyfileVerification);
        }
        Err(e) => return Err(e),
    };
    log::debug!("Schlüssel abgeleitet.");

    log::debug!("Lade und entschlüssele Vault-Datei...");
    let vault = match load_vault(&derived_key) {
        Ok(v) => v,
        Err(VaultError::PasswordOrKeyfileVerification) | Err(VaultError::Encryption(_)) => {
            log::warn!("{}", t!("log.password_or_keyfile_incorrect_decrypt"));
            return Err(VaultError::PasswordOrKeyfileVerification);
        }
         Err(VaultError::InvalidVaultFormat(msg)) => {
             log::error!("Vault-Datei hat ungültiges Format: {}", msg);
             return Err(VaultError::InvalidVaultFormat(msg));
         }
        Err(e) => {
             log::error!("Fehler beim Laden/Entschlüsseln des Vaults: {}", e);
            return Err(e);
        }
    };
    log::debug!("Vault entschlüsselt.");

    Ok(AppState {
        vault,
        key: Some(derived_key),
        last_activity: Instant::now(),
        locked: false,
    })
}


pub fn export_vault_plaintext_json(vault: &Vault, path: &Path) -> Result<(), VaultError> {
    log::info!("Exportiere Vault als unverschlüsselten JSON nach: {}", path.display());
    if path.as_os_str().is_empty() {
        return Err(VaultError::InvalidData(t!("errors.export_path_empty")));
    }
    let vault_json = serde_json::to_string_pretty(vault)?;
    fs::write(path, vault_json)?;
    log::debug!("Vault erfolgreich als JSON exportiert nach '{}'.", path.display());
    Ok(())
}


pub fn import_vault(vault: &mut Vault, path: &Path) -> Result<usize, VaultError> {
    log::info!("Importiere unverschlüsselten Vault aus '{}'.", path.display());
    if !path.exists() {
        return Err(VaultError::ImportFileNotFound(path.display().to_string()));
    }
     if !path.is_file() {
         return Err(VaultError::ImportPathNotFile(path.display().to_string()));
     }

    let file = File::open(path).map_err(|e| {
        log::error!("Fehler beim Öffnen der Importdatei '{}': {}", path.display(), e);
        VaultError::Io(e)
    })?;

    let reader = BufReader::new(file);
    let imported_vault: Vault = serde_json::from_reader(reader).map_err(|e| {
        log::error!("Fehler beim Deserialisieren der Importdatei '{}': {}", path.display(), e);
        VaultError::Deserialization(e)
    })?;

    let initial_pw_count = vault.passwords.len();
    let initial_note_count = vault.notes.len();

    vault.passwords.extend(imported_vault.passwords.clone());
    vault.notes.extend(imported_vault.notes.clone());

    let imported_passwords = vault.passwords.len() - initial_pw_count;
    let imported_notes = vault.notes.len() - initial_note_count;
    let total_imported = imported_passwords + imported_notes;

    log::info!("Insgesamt {} Einträge aus '{}' importiert.", total_imported, path.display());
    Ok(total_imported)
}

pub fn export_vault_csv(vault: &Vault, path: &Path) -> Result<(), VaultError> {
    log::info!("Exportiere Vault als CSV nach: {}", path.display());
    if path.as_os_str().is_empty() {
        return Err(VaultError::InvalidData(t!("errors.export_path_empty")));
    }

    let mut writer = WriterBuilder::new().delimiter(b';').from_path(path).map_err(VaultError::CsvExportError)?;

    writer.write_record(&[
        "Type", "Site", "Username", "Password", "Category", "URL", "Labels"
    ]).map_err(VaultError::CsvExportError)?;

    for entry in &vault.passwords {
        writer.write_record(&[
            "Password",
            &entry.site,
            entry.username.as_deref().unwrap_or(""),
            entry.password.as_str(),
            entry.category.as_deref().unwrap_or(""),
            entry.url.as_deref().unwrap_or(""),
            &entry.labels.as_ref().map_or_else(String::new, |l| l.join("|")),
        ]).map_err(VaultError::CsvExportError)?;
    }

    for note in &vault.notes {
         writer.write_record(&[
             "Note",
             &note.title,
             "",
             "",
             "",
             "",
             &note.content,
         ]).map_err(VaultError::CsvExportError)?;
    }

    writer.flush().map_err(VaultError::Io)?;

    log::debug!("Vault erfolgreich als CSV exportiert nach '{}'.", path.display());
    Ok(())
}

pub fn export_vault_encrypted(vault: &Vault, path: &Path, export_password: &Zeroizing<String>) -> Result<(), VaultError> {
    log::info!("Exportiere Vault verschlüsselt nach '{}'.", path.display());
     if path.as_os_str().is_empty() {
        return Err(VaultError::InvalidData(t!("errors.export_path_empty")));
    }

     let mut salt_bytes = [0u8; SALT_SIZE];
     OsRng.fill_bytes(&mut salt_bytes);
     let salt = salt_bytes.to_vec();

    log::debug!("Leite Export-Schlüssel mit Standard-Argon2-Parametern ab...");
    let export_key = derive_key_from_inputs_with_defaults(export_password, &salt, None)?;
    log::debug!("Export-Schlüssel abgeleitet.");

    let vault_json = serde_json::to_string(vault).map_err(|e| {
        log::error!("Fehler beim Serialisieren des Vaults für Export: {}", e);
        VaultError::Serialization(e)
    })?;
    log::trace!("Vault JSON für Export serialisiert ({} bytes).", vault_json.len());

    let plaintext_bytes = vault_json.into_bytes();
    let (nonce_bytes, ciphertext) = encrypt_data(&export_key, &plaintext_bytes)?;

    log::debug!("Vault-Daten für Export verschlüsselt (Ciphertext: {} bytes).", ciphertext.len());

    let export_data = EncryptedExportData {
        salt_hex: hex::encode(&salt),
        nonce_hex: hex::encode(&nonce_bytes),
        m_cost: ARGON2_M_COST,
        t_cost: ARGON2_T_COST,
        p_cost: ARGON2_P_COST,
        encrypted_vault_hex: hex::encode(&ciphertext),
    };
     log::debug!("Export-Daten-Struktur erstellt.");

    let export_json = serde_json::to_string_pretty(&export_data).map_err(|e| {
        log::error!("Fehler beim Serialisieren der Export-Daten-Struktur: {}", e);
        VaultError::Serialization(e)
    })?;
    log::trace!("Export-Daten-Struktur serialisiert ({} bytes).", export_json.len());

    let mut file = File::create(path).map_err(|e| {
        log::error!("Fehler beim Erstellen der verschlüsselten Exportdatei '{}': {}", path.display(), e);
        VaultError::Io(e)
    })?;
    file.write_all(export_json.as_bytes()).map_err(|e| {
         log::error!("Fehler beim Schreiben der verschlüsselten Exportdatei '{}': {}", path.display(), e);
         VaultError::Io(e)
    })?;
     file.flush().map_err(VaultError::Io)?;

    log::info!("Verschlüsselter Vault erfolgreich exportiert nach '{}'.", path.display());
    Ok(())
}

pub fn import_vault_encrypted(vault: &mut Vault, path: &Path, import_password: &Zeroizing<String>) -> Result<usize, VaultError> {
     log::info!("Importiere verschlüsselten Vault aus '{}'.", path.display());

    if !path.exists() {
        return Err(VaultError::ImportFileNotFound(path.display().to_string()));
    }
     if !path.is_file() {
         return Err(VaultError::ImportPathNotFile(path.display().to_string()));
     }

    let mut file = File::open(path).map_err(|e| {
         log::error!("Fehler beim Öffnen der verschlüsselten Importdatei '{}': {}", path.display(), e);
         VaultError::Io(e)
    })?;
    let mut export_json_str = String::new();
    file.read_to_string(&mut export_json_str).map_err(|e| {
         log::error!("Fehler beim Lesen der verschlüsselten Importdatei '{}': {}", path.display(), e);
         VaultError::Io(e)
    })?;
    log::trace!("Verschlüsselte Exportdatei gelesen ({} bytes).", export_json_str.len());

     let export_data: EncryptedExportData = serde_json::from_str(&export_json_str).map_err(|e| {
        log::error!("Fehler beim Deserialisieren der verschlüsselten Exportdaten '{}': {}", path.display(), e);
         VaultError::Deserialization(e)
    })?;
     log::debug!("Export-Daten-Struktur deserialisiert.");

    let salt = hex::decode(&export_data.salt_hex).map_err(|e| {
         log::error!("Fehler beim Hex-Decodieren des Salts aus Importdatei '{}': {}", path.display(), e);
         VaultError::HexDecode(e)
     })?;
     if salt.len() != SALT_SIZE {
         log::error!("Ungültige Salt-Länge in Importdatei '{}': {} Bytes (erwartet: {}).", path.display(), salt.len(), SALT_SIZE);
          return Err(VaultError::InvalidVaultFormat(t!("errors.import_invalid_salt_length", path = path.display(), expected = SALT_SIZE, got = salt.len())));
     }

    let nonce_bytes = hex::decode(&export_data.nonce_hex).map_err(|e| {
        log::error!("Fehler beim Hex-Decodieren der Nonce aus Importdatei '{}': {}", path.display(), e);
        VaultError::HexDecode(e)
    })?;
    if nonce_bytes.len() != NONCE_SIZE {
         log::error!("Ungültige Nonce-Länge in Importdatei '{}': {} Bytes (erwartet: {}).", path.display(), nonce_bytes.len(), NONCE_SIZE);
         return Err(VaultError::InvalidVaultFormat(t!("errors.import_invalid_nonce_length", path = path.display(), expected = NONCE_SIZE, got = nonce_bytes.len())));
    }

    let ciphertext = hex::decode(&export_data.encrypted_vault_hex).map_err(|e| {
        log::error!("Fehler beim Hex-Decodieren des Ciphertexts aus Importdatei '{}': {}", path.display(), e);
        VaultError::HexDecode(e)
    })?;
     log::trace!("Salt, Nonce und Ciphertext aus Hex decodiert.");

    log::debug!("Leite Import-Schlüssel mit Argon2-Parametern aus Exportdatei ab (m={}, t={}, p={})...",
        export_data.m_cost, export_data.t_cost, export_data.p_cost);

    let argon2_params_for_import = match Params::new(export_data.m_cost, export_data.t_cost, export_data.p_cost, Some(KEY_SIZE)) {
         Ok(p) => p,
         Err(e) => {
             log::error!("Ungültige Argon2-Parameter in Exportdatei '{}': {}", path.display(), e);
              return Err(VaultError::InvalidVaultFormat(t!("errors.import_invalid_argon2_params", path = path.display(), details = e.to_string())));
         }
    };

     let import_key = match derive_key_from_inputs_with_params( 
            import_password,
            &salt,
            None,
            Some(argon2_params_for_import)
        ) {
         Ok(key) => {
             log::debug!("Import-Schlüssel abgeleitet.");
             key
         }
         Err(VaultError::PasswordOrKeyfileVerification) => {
             log::warn!("{}", t!("log.import_password_incorrect"));
             return Err(VaultError::PasswordOrKeyfileVerification);
         }
         Err(e) => {
              log::error!("Fehler bei Schlüsselableitung für Import aus '{}': {}", path.display(), e);
             return Err(e);
         }
     };

    log::debug!("Entschlüssele importierte Vault-Daten...");
    let plaintext_bytes = match decrypt_data(&import_key, &nonce_bytes, &ciphertext) {
         Ok(data) => {
             log::debug!("Importierte Vault-Daten entschlüsselt.");
             data
         },
         Err(VaultError::PasswordOrKeyfileVerification) | Err(VaultError::Encryption(_)) => {
             log::warn!("{}", t!("log.import_decrypt_failed"));
              return Err(VaultError::PasswordOrKeyfileVerification);
         }
         Err(e) => {
             log::error!("Fehler bei Entschlüsselung der Import-Daten aus '{}': {}", path.display(), e);
             return Err(e);
         }
    };

    let imported_vault: Vault = serde_json::from_slice(&plaintext_bytes).map_err(|e| {
        log::error!("Fehler beim Deserialisieren des entschlüsselten Import-Vaults aus '{}': {}", path.display(), e);
        VaultError::Deserialization(e)
    })?;
     log::debug!("Importierter Vault deserialisiert.");

    let initial_pw_count = vault.passwords.len();
    let initial_note_count = vault.notes.len();

    vault.passwords.extend(imported_vault.passwords.clone());
    vault.notes.extend(imported_vault.notes.clone());

    let imported_passwords = vault.passwords.len() - initial_pw_count;
    let imported_notes = vault.notes.len() - initial_note_count;
    let total_imported = imported_passwords + imported_notes;

    log::info!("Insgesamt {} Einträge aus verschlüsseltem Import '{}' hinzugefügt.", total_imported, path.display());
    Ok(total_imported)
}