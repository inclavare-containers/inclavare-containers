There are still non-trivial number of systems without FLC support.

# Prerequisite
- Choose either SGX DCAP or in-tree Linux driver to use.
  * Apply the patch `0001-SGX-DCAP-Linux-Driver-Support-SGX1-machine-even-without-FLC-s.patch` to [SGX DCAP Linux driver](https://github.com/intel/SGXDataCenterAttestationPrimitives).
  * (**Depreciated**) Apply the patch `0001-sgx-Support-SGX1-machine-even-without-FLC-support.patch` to [v33 SGX in-tree driver](https://github.com/haitaohuang/linux-sgx-2/tree/v33).
- Apply the patch `0001-psw-Support-SGX1-machine-with-SGX-in-tree-driver.patch` to [Intel SGX SDK 2.10](https://github.com/intel/linux-sgx/tree/sgx_2.10) or higher.
  * Note: [Occlum](https://github.com/occlum/occlum) has a modified Intel SGX SDK repository named [`occlum/linux-sgx`](https://github.com/occlum/linux-sgx). So if applying the patch `0001-psw-Support-SGX1-machine-with-SGX-in-tree-driver.patch` to `occlum/linux-sgx`, `Occlum` can work with the `DCAP` or `in-tree` SGX Linux driver.

# Validation
- Successfully run the [`SampleEnclave`](https://github.com/intel/linux-sgx/tree/master/SampleCode/SampleEnclave) sample code
with `export LD_LIBRARY_PATH=/opt/intel/sgxpsw/aesm/:$LD_LIBRARY_PATH` as the precondition.
- Successfully run [sgx-tools](https://github.com/alibaba/inclavare-containers/tree/master/sgx-tools#test) to generate a launch token.
- Successfully run [skeleton bundle](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/skeleton/README.md).
  * Note: specify `"enclave.runtime.args": "no-sgx-flc"` in config.json is required.
- Successfully run occlum application example, refer to [Occlum application bundle](https://github.com/alibaba/inclavare-containers/blob/master/rune/README.md#creating-an-OCI-bundle).
