use lazy_static::lazy_static;
use parking_lot::RwLock;
use serde_json::Value;
use std::ffi::CStr;
use std::fs::{remove_file, File, OpenOptions};
use std::io::prelude::*;
use std::os::raw::c_char;
use std::process::Command;

/// Link import cgo function
#[link(name = "opa")]
extern "C" {
    pub fn makeDecisionGo(policy: GoString, message: GoString) -> *mut c_char;
}

const POLICY_PATH: &str = "src/policyEngine/opa/policy/";

/// Global file lock struct
pub struct FileLock {
    pub file: Option<File>,
}

impl FileLock {
    // Set the "file" field
    pub fn set_file(path: &str) {
        let mut w = FILELOCK.write();
        *w = FileLock {
            file: Some(
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .read(true)
                    .open(path)
                    .unwrap(),
            ),
        };
    }
}

lazy_static! {
    // Global file lock
    pub static ref FILELOCK: RwLock<FileLock> = RwLock::new(FileLock { file: None });
}

/// String structure passed into cgo
#[derive(Debug)]
#[repr(C)]
pub struct GoString {
    pub p: *const c_char,
    pub n: isize,
}

/// Introduce reference values, update or create new opa's policy files
/// references (JSON)
/// {
///     "mrEnclave" : xxx
///     "mrSigner" : xxx
///     "productId" : xxx
///     ...
/// }
pub fn set_reference(policy_name: &str, references: &str) -> bool {
    // Deserialize the references in json format
    let references: Value = match serde_json::from_str(references) {
        Ok(res) => res,
        Err(_) => {
            println!("Json unmashall failed");
            return false;
        }
    };

    // Generate policy file from reference value
    let mrEnclave: String = String::from("mrEnclave = ") + &references["mrEnclave"].to_string();
    let mrSigner: String = String::from("mrSigner = ") + &references["mrSigner"].to_string();
    let productId: String = String::from("productId = ") + &references["productId"].to_string();
    let policy = "package policy\n\n".to_string()
        + &mrEnclave
        + "\n"
        + &mrSigner
        + "\n"
        + &productId
        + "\n\n\
                default allow = false\n\n\
                allow = true {\n\
                \tmrEnclave == input.mrEnclave\n\
                \tmrSigner == input.mrSigner\n\
                \tproductId == input.productId\n\
                }";

    // Store the policy in the src/policy directory
    return write_to_file(policy_name, &policy);
}

/// Save the input raw policy file
/// Note that the OPA binary program needs to be installed and placed in the system path
pub fn set_raw_policy(policy_name: &str, policy: &str) -> bool {
    // Store the policy in the src/policy directory
    if write_to_file(policy_name, policy) == false {
        return false;
    };

    // Call the command line opa check to check the syntax
    let path = String::from(POLICY_PATH) + policy_name;
    let status = match Command::new("opa").arg("check").arg(&path).status() {
        Err(_) => {
            println!("Failed to check, note that the OPA binary program needs to be installed and placed in the system path");
            match remove_file(&path) {
                Err(_) => println!("Failed to delete the wrong policy"),
                Ok(_) => (),
            };
            return false;
        }
        Ok(res) => res,
    };

    // Determine whether the syntax is correct
    if !status.success() {
        println!("The uploaded policy has a syntax error");
        match remove_file(&path) {
            Err(_) => println!("Failed to delete the wrong policy"),
            Ok(_) => (),
        };
        return false;
    }

    true
}

/// Export existing policy from verdictd
/// If the policy does not exist, an empty string will be returned
pub fn export_policy(policy_name: &str) -> String {
    let path = String::from(POLICY_PATH) + policy_name;
    let mut contents = String::new();

    FileLock::set_file(&path);
    let reader = FILELOCK.read();
    let reader = &reader.file;
    let mut file_reader: &File;

    match reader {
        Some(s) => file_reader = s,
        None => return contents,
    };

    match file_reader.seek(std::io::SeekFrom::Start(0)) {
        Err(_) => {
            println!("Failed to move the read position to the beginning");
            return contents;
        }
        Ok(_) => (),
    };

    // Read the content of the policy to content
    match file_reader.read_to_string(&mut contents) {
        Err(_) => {
            println!("Failed to read the policy");
            return contents;
        }
        Ok(res) => res,
    };

    contents
}

/// According to message and policy, the decision is made by opa
/// message (JSON)
/// {
///     "mrEnclave" : "xxx"
///     "mrSigner" : "xxx"
///     "productId" : "xxx"
///     ...
/// }
///
/// returnValue(JSON)
/// {
///     "allow": true   
///     "parserInfo": {
///         "inputValue1": [
///             "xxxxx",
///             "xxxxx",
///         ],
///         "inputValue2": [
///             "xxxxx",
///             "xxxxx", ],
///     }
/// }
pub fn make_decision(policy_name: &str, message: &str) -> String {
    // Get the content of policy from policy_name
    let policy = export_policy(policy_name);
    let policy_go = GoString {
        p: policy.as_ptr() as *const i8,
        n: policy.len() as isize,
    };

    let message_go = GoString {
        p: message.as_ptr() as *const i8,
        n: message.len() as isize,
    };

    // Call the function exported by cgo and process the returned decision
    let decision_buf: *mut c_char = unsafe { makeDecisionGo(policy_go, message_go) };
    let decision_str: &CStr = unsafe { CStr::from_ptr(decision_buf) };
    let decision_slice: &str = match decision_str.to_str() {
        Err(_) => {
            println!("Failed to get the decision");
            return String::new();
        }
        Ok(res) => res,
    };

    decision_slice.to_string()
}

/// Write the string with the content of policy to the file named policy_name
fn write_to_file(policy_name: &str, policy: &str) -> bool {
    // Store the policy in the src/policy directory
    let path = String::from(POLICY_PATH) + policy_name;

    FileLock::set_file(&path);
    let writer = FILELOCK.write();
    let writer = &writer.file;
    let mut file_writer: &File;

    match writer {
        Some(s) => file_writer = s,
        None => return false,
    };

    match file_writer.seek(std::io::SeekFrom::Start(0)) {
        Err(_) => {
            println!("Failed to move the write position to the beginning");
            return false;
        }
        Ok(_) => (),
    };

    // Write the policy into file
    match file_writer.write_all(policy.as_bytes()) {
        Err(_) => {
            println!("Couldn't write to file");
            return false;
        }
        Ok(_) => (),
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_reference() {
        let policy_name = "demo.rego";
        let references = r#"
                {
                    "mrEnclave" : "123",
                    "mrSigner" : "456",
                    "productId" : "1"
                }
                "#;
        let result = set_reference(policy_name, references);

        assert!(result == true);
        // You can view the content in the src/policy/test.rego file by yourself
    }

    #[test]
    fn test_set_raw_policy() {
        let policy_name = "demo1.rego";

        // Right case
        let policy = "package policy\n\n".to_string()
            + "\
                    default allow = false\n\n\
                    allow = true {\n\
                    \t1==1\n\
                    }";
        let result = set_raw_policy(policy_name, &policy);

        assert!(result == true);

        // Wrong case, because of the syntax error of the policy file
        let policy = "package policy\n\n".to_string()
            + "\
                    default allow = false\n\n\
                    allow = true {\n\
                    \t1==\n\
                    }";
        let result = set_raw_policy(policy_name, &policy);

        assert!(result == false);
        // You can view the content in the src/policy/test1.rego file by yourself
    }

    #[test]
    fn test_export_policy() {
        let policy_name = "demo.rego";

        let result = export_policy(policy_name);
        let policy = "package policy\n\n\
        mrEnclave = \"123\"\n\
        mrSigner = \"456\"\n\
        productId = \"1\"\n\n\
        
        default allow = false\n\n\
        
        allow = true {\n\
            \tmrEnclave == input.mrEnclave\n\
            \tmrSigner == input.mrSigner\n\
            \tproductId == input.productId\n\
        }";

        assert!(result == policy);
    }

    #[test]
    fn test_make_decision() {
        let message = "{\"mrEnclave\":\"123\",\"mrSigner\":\"456\",\"productId\":\"1\"}";
        let result_str = make_decision("demo.rego", message);

        let result: Value = match serde_json::from_str(&result_str) {
            Ok(res) => res,
            Err(_) => {
                panic!("Json unmashall failed");
            }
        };

        assert!(result["allow"] == true);
    }
}
