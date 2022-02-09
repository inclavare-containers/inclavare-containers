# Verdict

A simple command line tool for issuing and exporting policies, currently only used as a preliminary alternative implementation of `Verdict`. The reference value should come from Reproducible Build Infrastructure (RBI), but this item is not reflected in the current implementation.

Currently, `Verdict` is a binary package written in Rust and also a CLT. Mainly provide the following functions:

* Pass the reference value to "verdictd" to complete the policy generation.
* Send the prepared policy file directly to "verdictd".
* Export the "verdictd" policy file to the local.
* Provide OPA policy and reference files' testing options.

## Usage

You can use `cargo build --release` to compile this project and place the generated executable file in the `/bin` directory.

The basic usage is as follows.

```bash
verdict [OPTIONS]

# Specify the config address, remember to add double quotes to the address.
# The default address is "[::1]:60000".
# It doesn't make sense to use this parameter alone.
-c, --client-api <ADDRESS> 

# Generate an OPA policy file named <POLICY_NAME>, according to the contents in <POLICY_PATH>.
--set-opa-policy <POLICY_NAME> <POLICY_PATH> [-c, --client-api <ADDRESS>]

# Export the contents of the policy file named <POLICY_NAME>.
# The export file is in the current directory by default and can be specified by <PATH>.
--export-opa-policy <POLICY_NAME> [-p, --path <PATH>] [-c, --client-api <ADDRESS>]

# Generate an OPA data file named <REFERENCE_NAME>, according to the contents in <REFERENCE_PATH>.
--set-opa-reference <REFERENCE_NAME> <REFERENCE_PATH> [-c, --client-api <ADDRESS>]

# Export the contents of the OPA data file named <REFERENCE_NAME>.
# The export file is in the current directory by default and can be specified by <PATH>.
--export-opa-reference <REFERENCE_NAME> [-p, --path <PATH>] [-c, --client-api <ADDRESS>]

# Test OPA's remote policy and remote reference with INPUT_PATH content
# POLICY_NAME: the tested policy file's name
# REFERENCE_NAME: the tested reference file's name
# INPUT_PATH: input data
--test-opa-remote <POLICY_NAME> <REFERENCE_NAME> <INPUT_PATH> [-c, --client-api <ADDRESS>]

# Test OPA with local policy and local reference
# POLICY_FILE: the path of policy file
# REFERENCE_PATH: the path of reference file
--test-opa-local <POLICY_PATH> <REFERENCE_PATH> <INPUT_PATH> [-c, --client-api <ADDRESS>]

# Test OPA's local policy and remote reference with INPUT_PATH content
# POLICY_FILE: the path of policy file
# REFERENCE_NAME: the tested reference file's name
--test-opa-local-policy <POLICY_PATH> <REFERENCE_NAME> [-c, --client-api <ADDRESS>]

# Test OPA's remote policy and local reference with INPUT_PATH content
# POLICY_NAME: the tested policy file's name
# REFERENCE_PATH: the path of reference file
--test-opa-local-reference <POLICY_NAME> <REFERENCE_PATH> [-c, --client-api <ADDRESS>]

# List GPG keyring's public keys
--list-gpg-keys [-c, --client-api <ADDRESS>]

# Import the KEY_FILE designated public key into GPG keyring
--import-gpg-key <KEY_FILE> [-c, --client-api <ADDRESS>]

# Delete the KEY_ID designated public key from GPG keyring
--delete-gpg-key <KEY_ID> [-c, --client-api <ADDRESS>]

# Export the GPG keyring, (base64 encoded)
--export-gpg-keyring [-p, --path <PATH>] [-c, --client-api <ADDRESS>]

# Export container image signature verification sigstore file
--export-image-sigstore [-p, --path <PATH>] [-c, --client-api <ADDRESS>]

# Set container image signature verification policy file
--set-image-sigstore <SIGSTORE_PATH> [-c, --client-api <ADDRESS>]

# Export container image signature verification policy file
--export-image-policy [-p, --path <PATH>] [-c, --client-api <ADDRESS>]

# Set container image signature verification policy file
--set-image-policy <POLICY_PATH> [-c, --client-api <ADDRESS>]

# Prints help information.
-h, --help

# Prints version information.
-V, --version
```
