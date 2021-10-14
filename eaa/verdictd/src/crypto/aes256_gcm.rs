use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};

pub fn encrypt(
    data: &[u8], 
    key: &[u8], 
    iv: &[u8]
) -> Result<Vec<u8>, String> {
    let encrypting_key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(encrypting_key);
    let nonce = Nonce::from_slice(iv);
    let encrypted_data = cipher
        .encrypt(nonce, data.as_ref())
        .map_err(|e| format!("Encrypt data failed: {:?}", e).to_string());

    encrypted_data
}

pub fn decrypt(
    encrypted_data: &[u8], 
    key: &[u8], 
    iv: &[u8]
) -> Result<Vec<u8>, String> {
    let decrypting_key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(decrypting_key);
    let nonce = Nonce::from_slice(iv);
    let plain_text = cipher
        .decrypt(nonce, encrypted_data.as_ref())
        .map_err(|e| format!("Decrypt data failed: {:?}", e).to_string());

    plain_text
}