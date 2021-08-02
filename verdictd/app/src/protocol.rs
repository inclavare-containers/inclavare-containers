
use serde_json::Value;
use crate::key_manager;
use crate::crypto::aes256_cbc;

fn handle_version() -> Result<String, String> {
    let mut response = serde_json::Map::new();
    response.insert("status".to_string(), Value::String("OK".to_string()));
    response.insert("version".to_string(), Value::String("v1".to_string()));

    Ok(Value::Object(response).to_string())
}

fn handle_decrypt(request: &Value) -> Result<String, String> {
    let blobs = match request["blobs"].as_array() {
        Some(blobs) => blobs,
        None => return Err("decrypt parameters error".to_string()),
    };

    let mut response = serde_json::Map::new();
    response.insert("status".to_string(), Value::String("OK".to_string()));    

    for blob in blobs {
        if blob["algorithm"] != "AES" || blob["key length"] != 256 || 
          blob["encrypted data"].is_null() || blob["iv"].is_null() {
            return Err("parameters error".to_string());
        }    
        
        match key_manager::directory_key_manager::get_key(&String::from(blob["kid"].as_str().unwrap()))
            .map_err(|_| format!("kid: {}'s key not found", blob["kid"].to_string()))
            .and_then(|key|{
                let iv = serde_json::from_str::<Vec<u8>>(blob["iv"].as_str().unwrap()).unwrap();
                let encrypted_data = serde_json::from_str::<Vec<u8>>(blob["encrypted data"].as_str().unwrap()).unwrap();
                aes256_cbc::decrypt(&encrypted_data, key.as_slice(), &iv)
                    .map_err(|_|"decryption failed".to_string())
                    .and_then(|decrypted_data|{
                        Ok(String::from_utf8(decrypted_data).unwrap())
                    })
            }) {
            Ok(decrypted_data) => response.insert(blob["encrypted data"].to_string(), Value::String(decrypted_data)),
            Err(e) => return Err(e),
        };        
    }

    Ok(Value::Object(response).to_string())
}

fn handle_getKek(request: &Value) -> Result<String, String> {
    let blobs = match request["kids"].as_array() {
        Some(blobs) => blobs,
        None => return Err("get KEK parameters error".to_string()),
    };

    let mut response = serde_json::Map::new();
    response.insert("status".to_string(), Value::String("OK".to_string()));   

    for index in 0..blobs.len() {
        let kid = blobs[index].as_str().unwrap();
        match key_manager::directory_key_manager::get_key(&String::from(kid))
            .map_err(|_| format!("kid: {}'s key not found", kid))
            .and_then(|key|{
                Ok(key)
            }) {
            Ok(key) => response.insert(String::from(kid), Value::String(serde_json::to_string(&key).unwrap())),
            Err(e) => return Err(e),
        };         
    };

    Ok(Value::Object(response).to_string())
}

pub fn handle_aa_request(request: &[u8]) -> Result<String, String> {
    let parsed_request: Value = match serde_json::from_slice(request) {
        Ok(r) => r,
        Err(_) => return Err("parse request failed".to_string()),
    };
    println!("request: {:?}", parsed_request);

    let response = match parsed_request["command"].as_str().unwrap() {
        "version" => handle_version(),
        "Decrypt" => handle_decrypt(&parsed_request),
        "Get KEK" => handle_getKek(&parsed_request),
        _ => Err("command error".to_string()),
    };

    response
}