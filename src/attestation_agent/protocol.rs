use base64;
use crate::crypto::aes256_gcm;
use crate::resources;
use serde_json::Value;
use crate::attestation_agent::rats_tls;

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
    let mut data = serde_json::Map::new();

    for blob in blobs {
        if blob["algorithm"] != "AES"
            || blob["key_length"] != 256
            || blob["encrypted_data"].is_null()
            || blob["iv"].is_null()
        {
            return Err("parameters error".to_string());
        }

        match resources::directory_key_manager::get_key(&String::from(
            blob["kid"].as_str().unwrap(),
        ))
        .map_err(|_| format!("kid: {}'s key not found", blob["kid"].to_string()))
        .and_then(|key| {
            let iv = base64::decode(blob["iv"].as_str().unwrap()).unwrap();
            let encrypted_data = base64::decode(blob["encrypted_data"].as_str().unwrap()).unwrap();
            aes256_gcm::decrypt(&encrypted_data, key.as_slice(), &iv)
                .map_err(|_| "decryption failed".to_string())
                .and_then(|decrypted_data| Ok(decrypted_data))
        }) {
            Ok(decrypted_data) => data.insert(
                blob["encrypted_data"].as_str().unwrap().to_string(),
                Value::String(base64::encode(decrypted_data)),
            ),
            Err(e) => return Err(e),
        };
    }
    response.insert("data".to_string(), Value::Object(data));

    Ok(Value::Object(response).to_string())
}

fn handle_getKek(request: &Value) -> Result<String, String> {
    let blobs = match request["kids"].as_array() {
        Some(blobs) => blobs,
        None => return Err("get KEK parameters error".to_string()),
    };

    let mut response = serde_json::Map::new();
    response.insert("status".to_string(), Value::String("OK".to_string()));
    let mut data = serde_json::Map::new();

    for index in 0..blobs.len() {
        let kid = blobs[index].as_str().unwrap();
        match resources::directory_key_manager::get_key(&String::from(kid))
            .map_err(|_| format!("kid: {}'s key not found", kid))
            .and_then(|key| Ok(key))
        {
            Ok(key) => data.insert(
                String::from(kid),
                Value::String(base64::encode(key)),
            ),
            Err(e) => return Err(e),
        };
    }
    response.insert("data".to_string(), Value::Object(data));

    Ok(Value::Object(response).to_string())
}

fn handle_echo(request: &Value) -> Result<String, String> {
    let data = match request["data"].as_str() {
        Some(data) => data,
        None => return Err("Echo parameters error".to_string()),
    };

    Ok(data.to_owned())
}

fn error_message(e: String) -> Result<String, ()> {
    let msg = serde_json::json!({
        "status": "Fail",
        "data": {},
        "error": e
    })
    .to_string();
    Ok(msg)
}

pub fn handle(request: &[u8]) -> Result<(String, u8), String> {
    let parsed_request: Value = match serde_json::from_slice(request) {
        Ok(r) => r,
        Err(_) => return Err("Parse request failed".to_string()),
    };
    info!("Request: {:?}", parsed_request);

    let response = match parsed_request["command"].as_str().unwrap() {
        "version" => {
            let response = handle_version().unwrap();
            Ok((response, rats_tls::ACTION_NONE))
        },
        "Decrypt" => {
            let response = handle_decrypt(&parsed_request)
                .unwrap_or_else(|e| {
                    error_message(e).unwrap()
                });
            Ok((response, rats_tls::ACTION_NONE))
        },
        "Get KEK" => {
            let response = handle_getKek(&parsed_request)
                .unwrap_or_else(|e| {
                    error_message(e).unwrap()
                });
            Ok((response, rats_tls::ACTION_NONE))
        },
        "echo" => {
            let response = handle_echo(&parsed_request)
                .unwrap_or_else(|e| {
                    e
                });
            Ok((response, rats_tls::ACTION_DISCONNECT))
        },
        _ => Err("Command error".to_string()),
    };

    response
}
