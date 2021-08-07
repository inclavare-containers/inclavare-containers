use std::fs;
use std::io;

const VERDICTD_KEY_PATH: &str = "/opt/verdictd/keys/";

pub fn get_key(kid: &String) -> Result<Vec<u8>, io::Error> {
    let path = VERDICTD_KEY_PATH.to_string() + kid;
    println!("get key from keyFile: {}", path);

    let data = fs::read(path);
    match data {
        Ok(key) => Ok(key),
        Err(e) => {
            println!("Get kid:{}'s key failed, err: {}", kid, e.to_string());
            Err(e)
        }
    }
}

pub fn set_key(kid: &String, key: &[u8]) -> std::io::Result<()> {
    let path = VERDICTD_KEY_PATH.to_string() + kid;
    println!("set key for keyFile: {}", path);

    fs::write(path, key).expect("Unable to write file");
    Ok(())
}
