There are still non-trivial number of systems without FLC support.

# Prerequisite
- Apply the patch `0001-sgx-Support-SGX1-machine-even-without-FLC-support.patch` to [v33 SGX in-tree driver](https://github.com/jsakkine-intel/linux-sgx/tree/v33).
- Apply the patch `0001-psw-Support-SGX1-machine-with-SGX-in-tree-driver.patch` to [Intel SGX SDK 2.10](https://github.com/intel/linux-sgx/tree/sgx_2.10) or higher.

# Validation
- Successfully run [sgx-tools](https://github.com/alibaba/inclavare-containers/tree/master/sgx-tools#test) to generate a launch token.
- Successfully run [skeleton bundle](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/skeleton/README.md).
  * Note: specify `"enclave.runtime.args": "no-sgx-flc"` in config.json is required.
