use super::{BrokerError, Result, read_bounded};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileKeyring {
    active_key_id: String,
    keys: BTreeMap<String, String>,
}
pub(crate) struct Keyring {
    pub active: String,
    keys: BTreeMap<String, LessSafeKey>,
}
impl Keyring {
    pub async fn load(path: &Path) -> Result<Self> {
        Self::parse(&read_bounded(path, 16384).await?)
    }
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let file: FileKeyring = serde_json::from_slice(bytes).map_err(|_| BrokerError::Invalid)?;
        if file.keys.is_empty() || file.keys.len() > 8 || !super::config::id(&file.active_key_id) {
            return Err(BrokerError::Invalid);
        }
        let mut keys = BTreeMap::new();
        for (id, value) in file.keys {
            if !super::config::id(&id) {
                return Err(BrokerError::Invalid);
            }
            let mut bytes = hex::decode(value).map_err(|_| BrokerError::Invalid)?;
            if bytes.len() != 32 {
                return Err(BrokerError::Invalid);
            }
            let key =
                UnboundKey::new(&aead::AES_256_GCM, &bytes).map_err(|_| BrokerError::Invalid)?;
            bytes.fill(0);
            keys.insert(id, LessSafeKey::new(key));
        }
        if !keys.contains_key(&file.active_key_id) {
            return Err(BrokerError::Invalid);
        }
        Ok(Self {
            active: file.active_key_id,
            keys,
        })
    }
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = self.keys.get(&self.active).ok_or(BrokerError::Integrity)?;
        let mut nonce = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| BrokerError::Unavailable)?;
        let mut body = plaintext.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut body,
        )
        .map_err(|_| BrokerError::Integrity)?;
        let mut result = nonce.to_vec();
        result.extend(body);
        Ok(result)
    }
    pub fn open(&self, key_id: &str, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 28 || ciphertext.len() > 65536 {
            return Err(BrokerError::Integrity);
        }
        let key = self.keys.get(key_id).ok_or(BrokerError::Integrity)?;
        let nonce: [u8; 12] = ciphertext[..12]
            .try_into()
            .map_err(|_| BrokerError::Integrity)?;
        let mut body = ciphertext[12..].to_vec();
        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut body,
            )
            .map_err(|_| BrokerError::Integrity)?;
        Ok(plaintext.to_vec())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn ring() -> Keyring {
        Keyring::parse(br#"{"active_key_id":"one","keys":{"one":"0101010101010101010101010101010101010101010101010101010101010101","two":"0202020202020202020202020202020202020202020202020202020202020202"}}"#).expect("keyring")
    }
    #[test]
    fn encrypted_values_bind_the_record_and_reject_tampering() {
        let ring = ring();
        let sealed = ring.seal(b"pod-profile-row", b"private-key").expect("seal");
        assert_eq!(
            ring.open("one", b"pod-profile-row", &sealed).expect("open"),
            b"private-key"
        );
        assert!(ring.open("one", b"different-pod", &sealed).is_err());
        assert!(ring.open("two", b"pod-profile-row", &sealed).is_err());
        let mut tampered = sealed;
        tampered[13] ^= 1;
        assert!(ring.open("one", b"pod-profile-row", &tampered).is_err());
    }
    #[test]
    fn key_rotation_reseals_without_losing_existing_rows() {
        let old = ring();
        let sealed = old.seal(b"row", b"private").expect("seal");
        let mut rotated = ring();
        rotated.active = "two".into();
        let value = rotated.open("one", b"row", &sealed).expect("old key");
        let resealed = rotated.seal(b"row", &value).expect("new key");
        assert_eq!(
            rotated.open("two", b"row", &resealed).expect("new value"),
            b"private"
        );
    }
}
