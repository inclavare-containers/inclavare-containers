use lazy_static::lazy_static;
use parking_lot::RwLock;
use serde_json::Value;
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

fn parser1(field_name: &str, references: &Value) -> Result<Vec<String>, String> {
    if references[field_name].is_array() {
        references[field_name].as_array()
            .ok_or("convert failed")
            .and_then(|res| {
                let mut vec: Vec<String> = Vec::new();
                let mut error_format = false;
                for i in res {
                    match i {
                        Value::String(item) => vec.push(item.to_string()),
                        _ => error_format = true,
                    }
                }
                if error_format {
                    Err("format is not supported")
                } else {
                    Ok(vec)
                }
            })
            .and_then(|vec| {
                Ok(vec![format!("{} = {:?}\n", field_name, vec),
                        format!("\tinput.{} == {}[_]\n", field_name, field_name)
                        ])
            })
    } else if references[field_name].is_string() {
         references[field_name].as_str()
            .ok_or("convert failed")
            .and_then(|str| {
                Ok(vec![format!("{} = {:?}\n", field_name, str),
                        format!("\tinput.{} == {:?}\n", field_name, str)
                        ])
            })
    } else if !references[field_name].is_null() {
        Err("format is not supported")
    } else {
        Ok(vec![String::new(), String::new()])
    }
    .map_err(|e| format!("{}", e).to_string())
}

fn parser2(field_name: &str, references: &Value) -> Result<Vec<String>, String> {
    let vec = if references[field_name].is_number() {
        Ok(vec![format!("{} = {}\n", field_name, references[field_name].as_u64().unwrap().to_string()),
                format!("\tinput.{} == {}\n", field_name, references[field_name].as_u64().unwrap().to_string())
                 ])
    } else if references[field_name].is_object() {
        let mut data = String::new();
        let mut rule = String::new();
        for (key, value) in references[field_name].as_object().unwrap().iter() {
            let value_num = match value {
                Value::Number(num) => num.as_u64().unwrap(),
                _ => return Err("format is not supported".to_string()),
            };
            // key should be: >=, >, <=, <
            match key.as_str() {
                ">=" => {}
                ">" => {}
                "<=" => {}
                "<" => {}
                _ => return Err("operation is not supported".to_string()),
            }
            let value_str = value.as_u64().unwrap().to_string();
            data += format!("{} = {{\"{}\": {:?}}}\n", field_name, key, value_num).as_str();
            rule += format!("\tinput.{} {} {}\n", field_name, key, value_str).as_str();
        }    
        Ok(vec![data, rule])
    } else if !references[field_name].is_null() {
        Err("format is not supported")
    } else {
        Ok(vec![String::new(), String::new()])
    }
    .map_err(|e| format!("{}", e).to_string());

    vec
}

// Introduce reference values, update or create new opa's policy files
pub fn set_reference(policy_name: &str, references: &str) -> Result<(), String> {
    let mut policy_data_section = String::new();
    let mut policy_rule_section = String::new();

    // Deserialize the references in json format
    let references: Value = serde_json::from_str(references)
        .map_err(|e| e.to_string())?;

    // Handle the "mrEnclave" field
    let vec = parser1("mrEnclave", &references)
        .map_err(|e| format!("mrEnclave parser error: {}", e))?;
    policy_data_section += &vec[0];
    policy_rule_section += &vec[1];

    // Handle the "mrSigner" field
    let vec = parser1("mrSigner", &references)
        .map_err(|e| format!("mrSigner parser error: {}", e))?;
    policy_data_section += &vec[0];
    policy_rule_section += &vec[1];

    // Handle the "productId" field
    let vec = parser2("productId", &references)
        .map_err(|e| format!("productId parser error: {}", e))?;
    policy_data_section += &vec[0];
    policy_rule_section += &vec[1];

    // Handle the "svn" field
    let vec = parser2("svn", &references)
        .map_err(|e| format!("svn parser error: {}", e))?;
    policy_data_section += &vec[0];
    policy_rule_section += &vec[1];

    // Generate policy file from reference value
    let policy = "package policy\n\n".to_string()
        + &policy_data_section
        + "\n\
                default allow = false\n\n\
                allow = true {\n"
        + &policy_rule_section
        + "}";

    // Store the policy in the src/policy directory
    write_to_file(policy_name, &policy)
}

/// Save the input raw policy file
/// Note that the OPA binary program needs to be installed and placed in the system path
pub fn set_raw_policy(policy_name: &str, policy: &str) -> Result<(), String> {
    let path = String::from(POLICY_PATH) + policy_name;
    write_to_file(policy_name, policy)
        .map_err(|e| format!("Store policy file failed, error: {}", e))
        .and_then(|_| {
            let status = Command::new("opa").arg("check").arg(&path).status()
                .map_err(|_e| {
                    let error = remove_file(&path)
                        .map_err(|e| format!("syntax check failed, remove file failed, error: {}", e.to_string()))
                        .and_then(|_| Err(format!("syntax check failed, error: {}", _e.to_string())))
                        .unwrap_or_else(|e| e);
                    error
                });
            status
        })
        .and_then(|status| {
            match status.success() {
                true => Ok(()),
                false => {
                    let error = remove_file(&path)
                        .map_err(|e| format!("syntax check failed, remove file failed, error: {}", e.to_string()))
                        .and_then(|_| Err("The uploaded policy has a syntax error".to_string()))
                        .unwrap_or_else(|e| e);
                    Err(error)               
                }
            }
        })
}

// Export existing policy from verdictd
pub fn export_policy(policy_name: &str) -> Result<String, String> {
    let path = String::from(POLICY_PATH) + policy_name;

    let lock = FILE_LOCK.read();
    assert_eq!(*lock, 0);

    File::open(path)
        .map_err(|e| e.to_string())
        .and_then(|mut file| {
            let mut contents = String::new();
            let res = file.read_to_string(&mut contents)
                .map_err(|e| e.to_string())
                .and_then(|_| Ok(contents));
            res
        })
}

// According to message and policy, the decision is made by opa
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
    decision_str.to_str()
        .map_err(|e| e.to_string())
        .and_then(|str| Ok(str.to_string()))
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
    File::create(&path)
        .map_err(|e| e.to_string())
        .and_then(|mut file| {
            let res = file.write_all(policy.as_bytes())
                .map_err(|e| e.to_string())
                .and_then(|_| Ok(()));
            res
        })
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
                "323232",
                "903232",
                "1212"
            ],
            "productId" : {
                ">=": 0
            },
            "svn" : {
                ">=": 0
            }
        }
        "#;
        let result = set_reference(policy_name, references);

        assert_eq!(result.unwrap(), ());
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

        assert_eq!(result.unwrap(), ());

        // Wrong case, because of the syntax error of the policy file
        let policy = "package policy\n\n".to_string()
            + "\
                    default allow = false\n\n\
                    allow = true {\n\
                    \t1==\n\
                    }";
        let result = set_raw_policy(policy_name, &policy);

        assert_eq!(result.is_err(), true);
        // You can view the content in the src/policy/test1.rego file by yourself
    }

    #[test]
    fn test_export_policy() {
        let policy_name = "demo3.rego";
        let references = r#"
        {
            "mrEnclave" : "123",
            "mrSigner" : "456",
            "productId" : 1
        }
        "#;
        set_reference(policy_name, references)
            .map_err(|e| {
                println!("set_reference error: {}", e);
                assert_eq!(true, false);
            });     

        let result = export_policy(policy_name).unwrap();
        let policy = "package policy\n\n\
        mrEnclave = \"123\"\n\
        mrSigner = \"456\"\n\
        productId = 1\n\n\
        
        default allow = false\n\n\
        
        allow = true {\n\
            \tinput.mrEnclave == \"123\"\n\
            \tinput.mrSigner == \"456\"\n\
            \tinput.productId == 1\n\
        }";

        assert_eq!(result, policy);
    }

    #[test]
    fn test_make_decision() {
        test_set_reference();
        let message = "{\"mrEnclave\":\"2343545\",\"mrSigner\":\"323232\",\"productId\":8,\"svn\":1}";
        let result_str = make_decision("demo.rego", message).unwrap();

        let result: Value = match serde_json::from_str(&result_str) {
            Ok(res) => res,
            Err(_) => {
                panic!("Json unmashall failed");
            }
        };

        assert_eq!(result["allow"], true);
    }
}
