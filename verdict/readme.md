# Verdict

A simple command line tool for issuing and exporting policies.

Mainly provide the following functions：

* Pass the reference value to "verdictd" to complete the policy generation.
* Send the prepared policy file directly to "verdictd".
* Export the "verdictd" policy file to the local.

## Usage

```bash
verdict [OPTIONS]

# Specify the config address, remember to add double quotes to the address.
# The default address is "[::1]:60000".
# It doesn't make sense to use this parameter alone.
-c, --config <CONFIG_ADDR> 

# Generate a policy file named <POLICY_NAME>, according to the contents in <FILE_REFERENCE>.
# The content of the <FILE_REFERENCE> must be in json format.
-s, --set_policy <POLICY_NAME> <FILE_REFERENCE> [-c, --config <CONFIG_ADDR>]

# Write the contents of <FILE> into the policy file named <POLICY_NAME>.
# The content of the <FILE> conforms to the OPA rego grammar rules.
-r, --set_raw_policy <POLICY_NAME> <FILE> [-c, --config <CONFIG_ADDR>]

# Export the contents of the policy file named <POLICY_NAME>.
# The export file is in the current directory by default and can be specified by <PATH>.
-e, --export_policy <POLICY_NAME> [-p, --path <PATH>] [-c, --config <CONFIG_ADDR>]

# Prints help information.
-h, --help

# Prints version information.
-V, --version
```
