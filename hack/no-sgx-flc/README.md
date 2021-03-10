There are still non-trivial number of systems without FLC support. This
page contains the information about the supports for no-FLC machines.

# Prerequisite

- Choose either SGX DCAP or in-tree Linux driver to use.
  * Apply [this patch](https://github.com/alibaba/inclavare-containers/blob/master/hack/no-sgx-flc/SGX-DCAP-1.41-Linux-Driver-Support-SGX1-machine-even-without-FLC-s.patch) to [SGX DCAP Linux Driver (>=1.41)](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver/linux).
  * Apply [this patch](https://github.com/alibaba/inclavare-containers/blob/master/hack/no-sgx-flc/SGX-DCAP-1.36-Linux-Driver-Support-SGX1-machine-even-without-FLC-s.patch) to [SGX DCAP Linux Driver (1.36)](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/DCAP_1.9/driver/linux).
  * Apply [this patch](https://github.com/alibaba/inclavare-containers/blob/master/hack/no-sgx-flc/linux-kernel-5.11-x86-sgx-Support-the-machines-without-FLC-support.patch) to Linux Kernel 5.11.
  * Apply [this patch](https://github.com/alibaba/inclavare-containers/blob/master/hack/no-sgx-flc/linux-kernel-5.12-rc2-x86-sgx-Support-the-machines-without-FLC-support.patch) to Linux Kernel 5.12-rc2.
- Apply [this patch](https://github.com/alibaba/inclavare-containers/blob/master/hack/no-sgx-flc/Linux-SGX-PSW-2.13-Support-SGX1-machine-with-SGX-in-tree-driver.patch) to [Intel SGX SDK (>=2.13)](https://github.com/intel/linux-sgx/tree/sgx_2.13) or higher.
- Build and install Intel SGX SDK and PSW from scratch.

Note: [Occlum](https://github.com/occlum/occlum) has a modified Intel SGX SDK repository named [`occlum/linux-sgx`](https://github.com/occlum/linux-sgx), so it is necessary to apply [the PSW patch](https://github.com/alibaba/inclavare-containers/blob/master/hack/no-sgx-flc/Linux-SGX-PSW-2.13-Support-SGX1-machine-with-SGX-in-tree-driver.patch) to `occlum/linux-sgx`.

# Validation

- First of all, run the [`SampleEnclave`](https://github.com/intel/linux-sgx/tree/master/SampleCode/SampleEnclave) sample code. This is the easiest way to prove everything is working. 
- Run [sgx-tools](https://github.com/alibaba/inclavare-containers/tree/master/sgx-tools#test) to generate a launch token.
- Run [skeleton bundle](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/skeleton/README.md).
  * Note: specify `"enclave.runtime.args": "no-sgx-flc"` in config.json is required.
- Run occlum application example, refer to [Occlum application bundle](https://github.com/alibaba/inclavare-containers/blob/master/rune/README.md#creating-an-OCI-bundle).
