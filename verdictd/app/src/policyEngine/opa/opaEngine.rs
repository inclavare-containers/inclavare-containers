use lazy_static::lazy_static;
use parking_lot::RwLock;
use serde_json::Value;
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
///     "mrEnclave" : [
///         "2343545",
///         "5465767",
///         ...
///     ],
///     "mrSigner" : [
///         323232,
///         903232,
///         ...
///     ],
///     "productId" : {
///         ">=": 0,
///         "<=": 10
///     },
///     "svn" : {
///         ">=": 0
///     }
/// }
pub fn set_reference(policy_name: &str, references: &str) -> Result<(), String> {
    // Deserialize the references in json format
    let references: Value = serde_json::from_str(references).map_err(|e| e.to_string())?;

    // Handle the "mrEnclave" field
    let mut mr_enclave: Vec<String> = Vec::new();
    if let Some(res) = references["mrEnclave"].as_array() {
        for i in res {
            if let Value::String(num) = i {
                mr_enclave.push(num.to_string());
            }
        }
    };
    let mut mr_enclave_str1 = String::new();
    let mut mr_enclave_str2 = String::new();
    if !mr_enclave.is_empty() {
        mr_enclave_str1 = format!("{}{:?}\n", "mrEnclave = ", mr_enclave);
        mr_enclave_str2 = "\tinput.mrEnclave == mrEnclave[_]\n".to_string();
    }

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
    let mut mr_signer_str1 = String::new();
    let mut mr_signer_str2 = String::new();
    if !mr_signer.is_empty() {
        mr_signer_str1 = format!("{}{:?}\n", "mrSigner = ", mr_signer);
        mr_signer_str2 = "\tinput.mrSigner == mrSigner[_]\n".to_string();
    }

    // Handle the "productId" field
    let mut product_id_str1 = String::new();
    let mut product_id_str2 = String::new();
    let mut product_id: HashMap<String, i64> = HashMap::new();
    match &references["productId"] {
        Value::Number(res) => {
            product_id_str1 = format!("{}{}\n", "productId = ", res);
            product_id_str2 = format!("\t{}{}\n", "input.productId == ", res)
        }
        Value::Object(res) => {
            for (key, value) in res.iter() {
                if let Value::Number(num) = value {
                    if let Some(i) = num.as_i64() {
                        product_id.insert(key.to_string(), i);
                    }
                }
            }
            for (key, value) in &product_id {
                let s = format!("\t{} {} {}\n", "input.productId", key, value);
                product_id_str2 = product_id_str2 + &s;
            }
            product_id_str1 = format!("{}{:?}\n", "productId = ", product_id);
        }
        _ => (),
    }

    // Handle the "svn" field
    let mut svn_str1 = String::new();
    let mut svn_str2 = String::new();
    let mut svn: HashMap<String, i64> = HashMap::new();
    match &references["svn"] {
        Value::Number(res) => {
            svn_str1 = format!("{}{}\n", "svn = ", res);
            svn_str2 = format!("\t{}{}\n", "input.svn == ", res)
        }
        Value::Object(res) => {
            for (key, value) in res.iter() {
                if let Value::Number(num) = value {
                    if let Some(i) = num.as_i64() {
                        svn.insert(key.to_string(), i);
                    }
                }
            }
            for (key, value) in &svn {
                let s = format!("\t{} {} {}\n", "input.svn", key, value);
                svn_str2 = svn_str2 + &s;
            }
            svn_str1 = format!("{}{:?}\n", "svn = ", svn);
        }
        _ => (),
    }

    // Generate policy file from reference value
    let policy = "package policy\n\n".to_string()
        + &mr_enclave_str1
        + &mr_signer_str1
        + &product_id_str1
        + &svn_str1
        + "\n\
                default allow = false\n\n\
                allow = true {\n"
        + &mr_enclave_str2
        + &mr_signer_str2
        + &product_id_str2
        + &svn_str2
        + "}";

    // Store the policy in the src/policy directory
    write_to_file(policy_name, &policy)
}

/// Save the input raw policy file
/// Note that the OPA binary program needs to be installed and placed in the system path
pub fn set_raw_policy(policy_name: &str, policy: &str) -> Result<(), String> {
    // Store the policy in the src/policy directory
    write_to_file(policy_name, policy)?;

    // Call the command line opa check to check the syntax
    let path = String::from(POLICY_PATH) + policy_name;
    let status = match Command::new("opa").arg("check").arg(&path).status() {
        Err(e) => {
            remove_file(&path).map_err(|e| e.to_string())?;
            return Err(e.to_string());
        }
        Ok(res) => res,
    };

    // Determine whether the syntax is correct
    if !status.success() {
        remove_file(&path).map_err(|e| e.to_string())?;
        return Err("The uploaded policy has a syntax error".to_string());
    }

    Ok(())
}

/// Export existing policy from verdictd
pub fn export_policy(policy_name: &str) -> Result<String, String> {
    let path = String::from(POLICY_PATH) + policy_name;
    let mut contents = String::new();

    let lock = FILE_LOCK.read();
    assert_eq!(*lock, 0);

    // Open the file named policy_name
    let mut file = File::open(path).map_err(|e| e.to_string())?;

    // Read the content of the policy to content
    file.read_to_string(&mut contents)
        .map_err(|e| e.to_string())?;

    Ok(contents)
}

/// According to message and policy, the decision is made by opa
/// message (JSON)
/// {
///     "mrEnclave" : "xxx"
///     "mrSigner" : "xxx"
///     "productId" : "xxx"
///     "svn" : "xxx"
///     ...
/// }
///
/// returnValue(JSON)
/// {
///     "allow": true   
///     "parserInfo": {
///         "inputValue1": [
///             input1,
///             reference1,
///         ],
///         "inputValue2": [
///             input2,
///             reference2, ],
///     }
/// }
pub fn make_decision(policy_name: &str, message: &str) -> Result<String, String> {
    // Get the content of policy from policy_name
    let policy = export_policy(policy_name)?;

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
    let decision_slice: &str = decision_str.to_str().map_err(|e| e.to_string())?;

    Ok(decision_slice.to_string())
}

/// Write the string with the content of policy to the file named policy_name
fn write_to_file(policy_name: &str, policy: &str) -> Result<(), String> {
    // Store the policy in the src/policy directory
    let path = String::from(POLICY_PATH) + policy_name;
    let path = Path::new(&path);

    let lock = FILE_LOCK.write();
    assert_eq!(*lock, 0);

    // Open the file in write-only mode
    // If a policy with the same name already exists, it will be overwritten
    let mut file = File::create(&path).map_err(|e| e.to_string())?;

    // Write the policy into file
    file.write_all(policy.as_bytes())
        .map_err(|e| e.to_string())?;

    Ok(())
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

        assert!(result.unwrap() == ());
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

        assert!(result.unwrap() == ());

        // Wrong case, because of the syntax error of the policy file
        let policy = "package policy\n\n".to_string()
            + "\
                    default allow = false\n\n\
                    allow = true {\n\
                    \t1==\n\
                    }";
        let result = set_raw_policy(policy_name, &policy);

        assert!(result.is_err() == true);
        // You can view the content in the src/policy/test1.rego file by yourself
    }

    #[test]
    fn test_export_policy() {
        let policy_name = "demo.rego";

        let result = export_policy(policy_name).unwrap();
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
        let message = "{\"mrEnclave\":\"2343545\",\"mrSigner\":323232,\"productId\":8,\"svn\":1}";
        let result_str = make_decision("demo.rego", message).unwrap();

        let result: Value = match serde_json::from_str(&result_str) {
            Ok(res) => res,
            Err(_) => {
                panic!("Json unmashall failed");
            }
        };

        assert!(result["allow"] == true);
    }
}
