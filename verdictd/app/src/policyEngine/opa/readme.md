# OPA Submodule

## Start

To ensure it can run, please install the OPA executable file. The steps are below.

### On Linux (64-bit)

```bash
curl -L -o opa https://openpolicyagent.org/downloads/v0.30.1/opa_linux_amd64_static
chmod 755 ./opa
mv opa /usr/local/bin/opa
```

### On macOS (64-bit)

```bash
curl -L -o opa https://openpolicyagent.org/downloads/v0.30.1/opa_darwin_amd64
chmod 755 ./opa
mv opa /usr/local/bin/opa
```

Before running, install the relevant Golang package: `go get github.com/open-policy-agent/opa/rego`

After that, you can use `cargo test -- --test-threads=1` to perform tests.

**Note:** The files under the path `/opt/verdictd/opa/policy/` are the `.rego` policy files.

## Upper API (Rust)

### set_reference

Introduce reference values, update or create new opa's policy file.

```rust
fn set_reference(policy_name: &str, references: &str) -> Result<(), String>

references (JSON)
{
    "mrEnclave" : [
        "2343545",
        "5465767",
        ... 
    ],
    "mrSigner" : [
        323232,
        903232,
        ...
    ],
    "productId" : {
        ">=": 0,
        "<=": 10
    },
    "svn" : {
        ">=": 0
    }
}
```

### set_raw_policy

Save the raw policy file.

```rust
fn set_raw_policy(policy_name: &str, policy: &str) -> Result<(), String>
```

### export_policy

Export existing policy from verdictd. If the policy named `policy_name`  does not exist, a None will be returned.

```rust
fn export_policy(policy_name: &str) -> Result<String, String>
```

### make_decision

According to the message and the policy,  return the decision made by opa.

```rust
fn make_decision(policy_name: &str, message: &str) -> Result<String, String>

message (JSON)
{
    "mrEnclave" : "xxx"
    "mrSigner" : "xxx"
    "productId" : "xxx"
    "svn" : "xxx"
    ...
}

returnValue(JSON)
{
  "allow": true
  "parserInfo": {
      "inputValue1": [
          input1,
          reference1,
      ],
      "inputValue2": [
          input2,
          reference2, 
      ],
  }
}
```

## Cgo API (C)

There is no need to use the C language, in other words, the C language layer is invisible.