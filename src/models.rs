use aes_gcm::{Key, Aes256Gcm};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use std::time::Instant;

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedExportData {
    pub salt_hex: String,
    pub nonce_hex: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub encrypted_vault_hex: String,
}

fn zeroizing_string_serialize<S>(zs: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(zs.as_str())
}

fn zeroizing_string_deserialize<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

#[derive(Serialize, Deserialize, Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PasswordEntry {
    pub site: String,
    pub username: Option<String>,
    #[serde(
        serialize_with = "zeroizing_string_serialize",
        deserialize_with = "zeroizing_string_deserialize"
    )]
    pub password: Zeroizing<String>,
    pub category: Option<String>,
    pub url: Option<String>,
    pub labels: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct NoteEntry {
    pub title: String,
    pub content: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Vault {
    pub passwords: Vec<PasswordEntry>,
    pub notes: Vec<NoteEntry>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey(pub Key<Aes256Gcm>);

pub struct AppState {
    pub vault: Vault,
    pub key: Option<EncryptionKey>,
    pub last_activity: Instant,
    pub locked: bool,
}

impl Default for AppState {
    fn default() -> Self {
        AppState {
            vault: Vault::default(),
            key: None,
            last_activity: Instant::now(),
            locked: true, 
        }
    }
}