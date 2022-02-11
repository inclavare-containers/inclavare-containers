# OPA Submodule

The Open Policy Agent (OPA, pronounced “oh-pa”) is an open source, general-purpose policy engine that unifies policy enforcement across the stack. OPA provides a high-level declarative language that lets you specify policy as code and simple APIs to offload policy decision-making from your software.

In the EAA project, OPA is an implementation of Policy Engine, which is a submodule of Verdictd. Use OPA to obtain the reference value from Verdict, and generate the policy from it. On the other hand, OPA obtains the evidence from the CSP side and makes decisions based on the existing policy.

## Start

To ensure it can run, please install the OPA executable file. The steps are below.

```bash
# On Linux (64-bit)
curl -L -o opa https://openpolicyagent.org/downloads/v0.30.1/opa_linux_amd64_static
# On macOS (64-bit)
curl -L -o opa https://openpolicyagent.org/downloads/v0.30.1/opa_darwin_amd64

chmod 755 ./opa
mv opa /usr/local/bin/opa
```

If there is a problem in the Go environment, for example, the `go.mod` or `go.sum` is deleted by mistake, you can use the following command:

```bash
# Optional, if the network is not smooth, you can try to set up a proxy
export GOPROXY=https://goproxy.io,direct

# Generate go.mod & go.sum
go mod init opa
go mod tidy
```

You can use `cargo test -- --test-threads=1` to perform tests.

**Note:** The files under the path `/opt/verdictd/opa/policy/` are the `.rego` policy files.

## APIs

|     Rust APIs     |                           function                           |    CGO    | Golang (OPA Core) |
| :---------------: | :----------------------------------------------------------: | :-------: | :---------------: |
| set_reference( )  |     generate/update policy file from the reference value     |     x     |         x         |
| set_raw_policy( ) |               import user-written policy files               |     x     |         x         |
| export_policy( )  |        export the generated policy file from Verdictd        |     x     |         x         |
| make_decision( )  | according to the input and policy files, output decision information | penetrate | makeDecisionGo( ) |

### Upper API

Written in Rust.

#### make_decision

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

### Lower API

Written in Rust.

#### set_reference

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

#### set_raw_policy

Save the raw policy file.

```rust
fn set_raw_policy(policy_name: &str, policy: &str) -> Result<(), String>
```

#### export_policy

Export existing policy from verdictd. If the policy named `policy_name`  does not exist, a None will be returned.

```rust
fn export_policy(policy_name: &str) -> Result<String, String>
```

### Cgo API (C)

There is no need to use the C language, in other words, the C language layer is invisible.