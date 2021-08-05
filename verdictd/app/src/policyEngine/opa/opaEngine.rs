use lazy_static::lazy_static;
use parking_lot::RwLock;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs::{remove_file, File};
use std::io::prelude::*;
use std::os::raw::c_char;
use std::path::Path;
use std::process::Command;

/// Link import cgo function
#[link(name = "opa")]
extern "C" {
    pub fn makeDecisionGo(policy: GoString, message: GoString) -> *mut c_char;
}

lazy_static! {
    // Global file lock
    pub static ref FILE_LOCK: RwLock<u32> = RwLock::new(0);
}

const POLICY_PATH: &str = "/opt/verdictd/opa/policy/";

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

    // Handle the "mrEnclave" field
    let mut mr_enclave: Vec<String> = Vec::new();
    if let Some(res) = references["mrEnclave"].as_array() {
        for i in res {
            if let Value::String(num) = i {
                mr_enclave.push(num.to_string());
            }
        }
    };

    // Handle the "mrSigner" field
    let mut mr_signer: Vec<i64> = Vec::new();
    if let Some(res) = references["mrSigner"].as_array() {
        for i in res {
            if let Value::Number(num) = i {
                if let Some(i) = num.as_i64() {
                    mr_signer.push(i);
                }
            }
        }
    };

    // Handle the "productId" field
    let mut product_id: HashMap<String, i64> = HashMap::new();
    if let Some(res) = references["productId"].as_object() {
        for (key, value) in res.iter() {
            if let Value::Number(num) = value {
                if let Some(i) = num.as_i64() {
                    product_id.insert(key.to_string(), i);
                }
            }
        }
    }

    // Handle the "svn" field
    let mut svn: HashMap<String, i64> = HashMap::new();
    if let Some(res) = references["svn"].as_object() {
        for (key, value) in res.iter() {
            if let Value::Number(num) = value {
                if let Some(i) = num.as_i64() {
                    svn.insert(key.to_string(), i);
                }
            }
        }
    }

    // Generate policy file from reference value
    let mr_enclave_str = format!("{}{:?}", "mrEnclave = ", mr_enclave);
    let mr_signer_str = format!("{}{:?}", "mrSigner = ", mr_signer);
    let mut product_id_str = String::new();
    for (key, value) in &product_id {
        let s = format!("\t{} {} {}\n", "input.productId", key, value);
        product_id_str = product_id_str + &s;
    }
    let mut svn_str = String::new();
    for (key, value) in &svn {
        let s = format!("\t{} {} {}\n", "input.svn", key, value);
        svn_str = svn_str + &s;
    }
    let policy = "package policy\n\n".to_string()
        + &mr_enclave_str
        + "\n"
        + &mr_signer_str
        + "\n\n\
                default allow = false\n\n\
                allow = true {\n"
        + &product_id_str
        + &svn_str
        + "\tinput.mrEnclave == mrEnclave[_]\n\
                \tinput.mrSigner == mrSigner[_]\n\
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

    let lock = FILE_LOCK.read();
    assert_eq!(*lock, 0);

    // Open the file named policy_name
    let mut file = match File::open(path) {
        Err(_) => {
            println!("Failed to open the policy");
            return contents;
        }
        Ok(res) => res,
    };

    // Read the content of the policy to content
    match file.read_to_string(&mut contents) {
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
    let path = Path::new(&path);

    let lock = FILE_LOCK.write();
    assert_eq!(*lock, 0);

    // Open the file in write-only mode
    // If a policy with the same name already exists, it will be overwritten
    let mut file = match File::create(&path) {
        Err(_) => {
            println!("Couldn't create file");
            return false;
        }
        Ok(file) => file,
    };

    // Write the policy into file
    match file.write_all(policy.as_bytes()) {
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
            "mrEnclave" : [
                "2343545",
                "5465767",
                "79gfgfvf"
            ],
            "mrSigner" : [
                323232,
                903232,
                1212
            ],
            "productId" : {
                ">=": 0,
                "<=": 10
            },
            "svn" : {
                ">=": 0
            }
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
