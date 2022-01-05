use lazy_static::lazy_static;
use parking_lot::RwLock;
use serde_json::Value;
use std::ffi::CStr;
use std::fs;
use std::io::prelude::*;
use std::os::raw::c_char;
use std::path::Path;
use std::process::Command;

/// Link import cgo function
#[link(name = "opa")]
extern "C" {
    pub fn makeDecisionGo(policy: GoString, data: GoString, input: GoString) -> *mut c_char;
}

lazy_static! {
    // Global file lock
    pub static ref FILE_LOCK: RwLock<u32> = RwLock::new(0);
}

pub const OPA_PATH: &str = "/opt/verdictd/opa/";
pub const OPA_POLICY_SGX: &str = "sgxPolicy.rego";
pub const OPA_DATA_SGX: &str = "sgxData";

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

pub fn set_reference(name: &str, reference: &str) -> Result<(), String> {
    let lock = FILE_LOCK.write();
    assert_eq!(*lock, 0);

    let src = String::from(OPA_PATH) + name;
    let bak = String::from(OPA_PATH) + name + ".bak";

    if Path::new(&src).exists() {
        fs::copy(&src, &bak).unwrap();
    }

    write(&src, reference)
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

/// Save the input raw policy file
/// Note that the OPA binary program needs to be installed and placed in the system path
pub fn set_raw_policy(name: &str, policy: &str) -> Result<(), String> {
    let lock = FILE_LOCK.write();
    assert_eq!(*lock, 0);

    let src = String::from(OPA_PATH) + name;
    let bak = String::from(OPA_PATH) + name + ".bak";

    if Path::new(&src).exists() {
        fs::copy(&src, &bak).unwrap();
    }

    write(&src, policy)
        .map_err(|e| {
            if Path::new(&bak).exists() {
                fs::copy(&bak, &src).unwrap();
            }
            format!("Store policy failed: {}", e)
        })
        .and_then(|_| {
            let status = 
                Command::new("opa")
                .arg("check")
                .arg(&src)
                .status()
                .map_err(|_e| {
                    if Path::new(&bak).exists() {
                        fs::copy(&bak, &src).unwrap();
                    }
                    format!("Policy syntax check execution failed: {}", _e.to_string())
                });
            status
        })
        .and_then(|status| {
            match status.success() {
                true => {
                    if Path::new(&bak).exists() {
                        fs::remove_file(&bak).unwrap();
                    }
                    Ok(())
                }
                false => {
                    if Path::new(&bak).exists() {
                        fs::copy(&bak, &src).unwrap();
                    }
                    Err(format!("Policy syntax check failed"))         
                }
            }
        })
}

// Export existing policy from verdictd
pub fn export(name: &str) -> Result<String, String> {
    let path = String::from(OPA_PATH) + name;

    let lock = FILE_LOCK.read();
    assert_eq!(*lock, 0);

    fs::File::open(path)
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
pub fn make_decision(policy_name: &str, data_name: &str, input: &str) -> Result<String, String> {
    // Get the content of policy from policy_name
    let policy = export(policy_name)?;

    let policy_go = GoString {
        p: policy.as_ptr() as *const i8,
        n: policy.len() as isize,
    };

    let data = export(data_name)?;
    let data_go = GoString {
        p: data.as_ptr() as *const i8,
        n: data.len() as isize,
    };

    let input_go = GoString {
        p: input.as_ptr() as *const i8,
        n: input.len() as isize,
    };

    // Call the function exported by cgo and process the returned decision
    let decision_buf: *mut c_char = unsafe { makeDecisionGo(policy_go, data_go, input_go) };
    let decision_str: &CStr = unsafe { CStr::from_ptr(decision_buf) };
    decision_str.to_str()
        .map_err(|e| e.to_string())
        .and_then(|str| Ok(str.to_string()))
}

pub fn make_decision_ext(
    policy_name: &str,
    policy_content: &str,
    policy_remote: bool,
    reference_name: &str,
    reference_content: &str,
    reference_remote: bool,
    input: &str) -> Result<String, String> {
    let policy = if policy_remote == true {
        policy_content.to_owned()
    }else{
        export(policy_name).unwrap()
    };

    let reference = if reference_remote == true {
        reference_content.to_owned()
    }else{
        export(reference_name).unwrap()
    };

    let policy_go = GoString {
        p: policy.as_str().as_ptr() as *const i8,
        n: policy.as_str().len() as isize,
    };

    let reference_go = GoString {
        p: reference.as_str().as_ptr() as *const i8,
        n: reference.as_str().len() as isize,
    };

    let input_go = GoString {
        p: input.as_ptr() as *const i8,
        n: input.len() as isize,
    };

    // Call the function exported by cgo and process the returned decision
    let decision_buf: *mut c_char = unsafe { makeDecisionGo(policy_go, reference_go, input_go) };
    let decision_str: &CStr = unsafe { CStr::from_ptr(decision_buf) };
    decision_str.to_str()
        .map_err(|e| e.to_string())
        .and_then(|str| Ok(str.to_string()))
}

fn write(src: &str, content: &str) -> Result<(), String> {
    // Open the file in write-only mode
    // If a policy with the same name already exists, it will be overwritten
    fs::File::create(src)
        .map_err(|e| e.to_string())
        .and_then(|mut file| {
            let res = file.write_all(content.as_bytes())
                .map_err(|e| e.to_string())
                .and_then(|_| Ok(()));
            res
        })
}

pub fn default() -> Result<(), String> {
    if !Path::new(&OPA_PATH.to_string()).exists() {
        fs::create_dir_all(OPA_PATH)
            .map_err(|_| format!("create {:?} failed", OPA_PATH))?;
    }

    if !Path::new(&(OPA_PATH.to_string() + OPA_POLICY_SGX)).exists() {
        info!("{} isn't exist", OPA_POLICY_SGX);
        let policy = r#"
package policy

# By default, deny requests.
default allow = false

allow {
    mrEnclave_is_grant
    mrSigner_is_grant
    input.productId >= data.productId
    input.svn >= data.svn
}

mrEnclave_is_grant {
    count(data.mrEnclave) == 0
}
mrEnclave_is_grant {
    count(data.mrEnclave) > 0
    input.mrEnclave == data.mrEnclave[_]
}

mrSigner_is_grant {
    count(data.mrSigner) == 0
}
mrSigner_is_grant {
    count(data.mrSigner) > 0
    input.mrSigner == data.mrSigner[_]
}
"#;
        write(&(String::from(OPA_PATH) + OPA_POLICY_SGX), &policy.to_string())
            .map_err(|e| format!("Set {} failed with error {:?}", OPA_POLICY_SGX, e))?;
    }

    if !Path::new(&(OPA_PATH.to_string() + OPA_DATA_SGX)).exists() {
        info!("{} isn't exist", OPA_DATA_SGX);
        let sgx_data = r#"{
    "mrEnclave": [],
    "mrSigner": [],
    "productId": 0,
    "svn": 0
}"#;

        let lock = FILE_LOCK.write();
        assert_eq!(*lock, 0);
        
        write(&(String::from(OPA_PATH) + OPA_DATA_SGX), &sgx_data.to_string())
            .map_err(|e| format!("Set {} failed with error {:?}", OPA_DATA_SGX, e))?;
    }    

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_reference() {
        let policy_name = "sgx_reference_test";
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
            "productId" : 1,
            "svn" : 3
        }
        "#;
        let result = set_reference(policy_name, references);

        assert_eq!(result.unwrap(), ());
        // You can view the content in the src/policy/test.rego file by yourself
    }

    #[test]
    fn test_set_raw_policy() {
        let name = "sgx_policy_test.rego";

        // Right case
        let policy = r#"
package policy

# By default, deny requests.
default allow = false

allow {
    mrEnclave_is_grant
    mrSigner_is_grant
    input.productId >= data.productId
    input.svn >= data.svn
}

mrEnclave_is_grant {
    count(data.mrEnclave) == 0
}
mrEnclave_is_grant {
    count(data.mrEnclave) > 0
    input.mrEnclave == data.mrEnclave[_]
}

mrSigner_is_grant {
    count(data.mrSigner) == 0
}
mrSigner_is_grant {
    count(data.mrSigner) > 0
    input.mrSigner == data.mrSigner[_]
}
"#;
        let result = set_raw_policy(name, &policy);

        assert_eq!(result.unwrap(), ());

        // Wrong case, because of the syntax error of the policy file
        let policy = r#"
package policy

# By default, deny requests.
default allow = false

allow {
    mrEnclave_is_grant
    mrSigner_is_grant
    input.productId >= data.productId
    input.svn >= data.svn
}
"#;
        let result = set_raw_policy(name, &policy);

        assert_eq!(result.is_err(), true);
        // You can view the content in the src/policy/test1.rego file by yourself
    }

    #[test]
    fn test_export() {
        let name = "sgx_data_test";
        let reference = r#"
        {
            "mrEnclave" : ["123"],
            "mrSigner" : ["123"],
            "productId" : 1,
            "svn" : 2
        }
        "#;
        set_reference(name, reference)
            .map_err(|e| {
                error!("set_reference error: {}", e);
                assert_eq!(true, false);
            }).unwrap();     

        let result = export(name).unwrap();
        let expected = r#"
        {
            "mrEnclave" : ["123"],
            "mrSigner" : ["123"],
            "productId" : 1,
            "svn" : 2
        }
        "#;

        assert_eq!(result, expected);
    }
}
