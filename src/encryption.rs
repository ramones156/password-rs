use aes_gcm::aead::consts::U12;
use aes_gcm::aead::Nonce;
use aes_gcm::aes::Aes256;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, AesGcm, Key,
};

pub struct EncryptionManager {
    nonce: Nonce<AesGcm<Aes256, U12>>,
    cipher: AesGcm<Aes256, U12>,
}

impl EncryptionManager {
    pub fn new() -> Self {
        let key = Aes256Gcm::generate_key(OsRng);
        let key = Key::<Aes256Gcm>::from_slice(key.as_ref());

        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        Self { cipher, nonce }
    }
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        self.cipher.encrypt(&self.nonce, plaintext.as_ref())
    }
    pub fn decrypt(&self, ciphertext: &Vec<u8>) -> Result<Vec<u8>, aes_gcm::Error> {
        self.cipher.decrypt(&self.nonce, ciphertext.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_succeed() {
        let manager = EncryptionManager::new();

        let ciphertext = manager.encrypt(b"plaintext message".as_ref()).unwrap();
        let plaintext = manager.decrypt(ciphertext.as_ref()).unwrap();
        assert_eq!(&plaintext, b"plaintext message");
    }
}
