use lazy_static::lazy_static;
use parking_lot::RwLock;
use std::fs;
use std::io::prelude::*;
use std::path::Path;

lazy_static! {
    // Global file lock
    pub static ref FILE_LOCK: RwLock<u32> = RwLock::new(0);
}

pub const IMAGE_PATH: &str = "/opt/verdictd/image/";
pub const POLICY: &str = "/opt/verdictd/image/policy.json";
pub const SIGSTORE: &str = "/opt/verdictd/image/sigstore.yaml";

fn write(src: &str, content: &str) -> Result<(), String> {
    // Open the file in write-only mode
    // If the file with the same name already exists, it will be overwritten
    fs::File::create(src)
        .map_err(|e| e.to_string())
        .and_then(|mut file| {
            let res = file.write_all(content.as_bytes())
                .map_err(|e| e.to_string())
                .and_then(|_| Ok(()));
            res
        })
}

pub fn export(name: &str) -> Result<String, String> {
    let lock = FILE_LOCK.read();
    assert_eq!(*lock, 0);

    fs::File::open(name)
        .map_err(|e| e.to_string())
        .and_then(|mut file| {
            let mut contents = String::new();
            let res = file.read_to_string(&mut contents)
                .map_err(|e| e.to_string())
                .and_then(|_| Ok(contents));
            res
        })
}

pub fn set(name: &str, content: &str) -> Result<(), String> {
    let lock = FILE_LOCK.write();
    assert_eq!(*lock, 0);

    let src = name;
    let bak = name.clone().to_owned() + ".bak";

    if Path::new(&src).exists() {
        fs::copy(&src, &bak).unwrap();
    }

    write(&src, content)
        .map_err(|e| {
            if Path::new(&bak).exists() {
                fs::copy(&bak, &src).unwrap();
            }
            e
        })
        .and_then(|_| {
            if Path::new(&bak).exists() {
                fs::remove_file(&bak).unwrap();
            }
            Ok(())
        })
}

pub fn default() -> Result<(), String> {
    if !Path::new(&IMAGE_PATH.to_string()).exists() {
        fs::create_dir_all(IMAGE_PATH)
            .map_err(|_| format!("create {:?} failed", IMAGE_PATH))?;
    }

    if !Path::new(&POLICY.to_string()).exists() {
        info!("{} isn't exist", POLICY);
        let policy = r#"{
    "default": [
        {
            "type": "insecureAcceptAnything"
        }
    ],
}"#;

        let lock = FILE_LOCK.write();
        assert_eq!(*lock, 0);
        
        write(&String::from(POLICY), &policy.to_string())
            .map_err(|e| format!("Set {} failed with error {:?}", POLICY, e))?;
    }

    if !Path::new(&SIGSTORE.to_string()).exists() {
        info!("{} isn't exist", SIGSTORE);
        let sigstore =
"default:
    sigstore: file:///var/lib/containers/sigstore
";

        let lock = FILE_LOCK.write();
        assert_eq!(*lock, 0);
        
        write(&String::from(SIGSTORE), sigstore)
            .map_err(|e| format!("Set {} failed with error {:?}", SIGSTORE, e))?;
    }

    Ok(())
}
