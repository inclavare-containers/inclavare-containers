use std::fs;
use std::io::prelude::*;
use std::path::Path;
use base64;

pub const GPG_PATH: &str = "/opt/verdictd/gpg/";
pub const GPG_KEYRING: &str = "/opt/verdictd/gpg/keyring.gpg";

pub fn export_base64(name: &str) -> Result<String, String> {
    fs::File::open(name)
        .map_err(|e| e.to_string())
        .and_then(|mut file| {
            let mut contents = Vec::new();
            let res = file.read_to_end(&mut contents)
                .map_err(|e| e.to_string())
                .and_then(|_| Ok(base64::encode(contents)));
            res
        })
}

pub fn default() -> Result<(), String> {
    if !Path::new(&GPG_PATH.to_string()).exists() {
        fs::create_dir_all(GPG_PATH)
            .map_err(|_| format!("create {:?} failed", GPG_PATH))?;
    }

    Ok(())
}
