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
fn set_reference(policy_name: &str, references: &str) -> bool

references (JSON)
{
  "mrEnclave" : xxx
  "mrSigner" : xxx
  "productId" : xxx
  ...
}
```

### set_raw_policy

Save the raw policy file.

```rust
fn set_raw_policy(policy_name: &str, policy: &str) -> bool
```

### export_policy

Export existing policy from verdictd. If the policy named `policy_name`  does not exist, an empty string will be returned.

```rust
fn export_policy(policy_name: &str) -> String
```

### make_decision

According to the message and the policy,  return the decision made by opa.

```rust
fn make_decision(policy_name: &str, message: &str) -> String

message (JSON)
{
  "mrEnclave" : "xxx"
  "mrSigner" : "xxx"
  "productId" : "xxx"
  ...
}

returnValue(JSON)
{
  "allow": true
  "parserInfo": {
      "inputValue1": [
          "xxxxx",
          "xxxxx",
      ],
      "inputValue2": [
          "xxxxx",
          "xxxxx", 
      ],
  }
}
```

## Cgo API (C)

There is no need to use the C language, in other words, the C language layer is invisible.