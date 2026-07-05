//! Cryptography primitives for C2 traffic.
//!
//! Uses:
//! - X25519 for key exchange
//! - ChaCha20-Poly1305 for AEAD encryption
//! - HKDF-SHA256 for key derivation

use aes::Aes256;
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

#[derive(Clone)]
pub struct CryptoEngine {
    key: [u8; 32],
}

impl CryptoEngine {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    pub fn derive(shared_secret: &[u8], salt: &[u8]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
        let mut key = [0u8; 32];
        hkdf.expand(b"monolith-c2-v1", &mut key).expect("HKDF expand");
        Self { key }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext).expect("encrypt");
        [nonce_bytes.to_vec(), ciphertext].concat()
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 12 {
            return Err("ciphertext too short".into());
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "decrypt failed".into())
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC key");
        mac.update(message);
        mac.finalize().into_bytes().to_vec()
    }

    pub fn b64encode(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(data)
    }

    pub fn b64decode(data: &str) -> Result<Vec<u8>, String> {
        general_purpose::STANDARD.decode(data).map_err(|e| e.to_string())
    }
}
