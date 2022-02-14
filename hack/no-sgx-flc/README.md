# Background

Linux kernel since 5.11 with SGX in-tree driver drops the support for the
SGX platforms without FLC hardware capability, e.g, SGX1 machine. However,
there are still non-trivial number of systems without FLC support.

This page contains the information about how to re-enable no-FLC machines
with SGX in-tree driver the latest SGX DCAP Linux Driver.

If you still intend to use [legacy SGX out-of-tree Linux Driver (isgx)](https://github.com/intel/linux-sgx-driver), please skip the following sections and read [this](https://github.com/alibaba/inclavare-containers/blob/master/hack/no-sgx-flc/README.md#for-isgx-linux-driver-users).

# Prerequisites

- Choose either SGX DCAP or in-tree Linux driver to use.
  * Apply [this patch](https://github.com/alibaba/inclavare-containers/blob/master/hack/no-sgx-flc/SGX-DCAP-1.41-Linux-Driver-Support-SGX1-machine-even-without-FLC-s.patch) to [SGX DCAP Linux Driver (>=1.41)](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver/linux).
  * Apply [this patch](https://github.com/alibaba/inclavare-containers/blob/master/hack/no-sgx-flc/SGX-DCAP-1.36-Linux-Driver-Support-SGX1-machine-even-without-FLC-s.patch) to [SGX DCAP Linux Driver (1.36)](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/DCAP_1.9/driver/linux).
  * Apply [this patch](https://github.com/alibaba/inclavare-containers/blob/master/hack/no-sgx-flc/linux-kernel-5.11-x86-sgx-Support-the-machines-without-FLC-support.patch) to Linux Kernel 5.11.
  * Apply [this patch](https://github.com/alibaba/inclavare-containers/blob/master/hack/no-sgx-flc/linux-kernel-5.12-rc2-x86-sgx-Support-the-machines-without-FLC-support.patch) to Linux Kernel 5.12-rc2.
  * Apply [this patch](https://github.com/alibaba/inclavare-containers/blob/master/hack/no-sgx-flc/linux-kernel-5.13-x86-sgx-Support-the-machines-without-FLC-support.patch) to Linux Kernel 5.13.

- Apply [this patch](https://github.com/alibaba/inclavare-containers/blob/master/hack/no-sgx-flc/Linux-SGX-PSW-2.13-Support-SGX1-machine-with-SGX-in-tree-driver.patch) to [Intel SGX SDK (>=2.13)](https://github.com/intel/linux-sgx/tree/sgx_2.13) or higher.
- Build and install Intel SGX SDK and PSW from scratch.

Note: For Occlum users, [Occlum](https://github.com/occlum/occlum) hosts a [modified Intel SGX SDK repository](https://github.com/occlum/linux-sgx). Please apply [the PSW patch](https://github.com/alibaba/inclavare-containers/blob/master/hack/no-sgx-flc/Linux-SGX-PSW-2.13-Support-SGX1-machine-with-SGX-in-tree-driver.patch) to it.

# Validations

- Run the [`SampleEnclave`](https://github.com/intel/linux-sgx/tree/master/SampleCode/SampleEnclave) sample code. This is the easiest way to prove everything is working.
- (Optional) Run [sgx-tools](https://github.com/alibaba/inclavare-containers/tree/master/sgx-tools#test) to generate a launch token.
- (Optional) Run [skeleton bundle](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/skeleton/README.md).
  * Note: specify `"enclave.runtime.args": "no-sgx-flc"` in config.json is required.
- (Optional) Run occlum application example, refer to [Occlum application bundle](https://github.com/alibaba/inclavare-containers/blob/master/rune/README.md#creating-an-OCI-bundle).

# For isgx Linux Driver users

If you are [isgx](https://github.com/intel/linux-sgx-driver) users,
and don't want to make the efforts on software rebuild, please
use the isgx driver newer than 2.11, or manually apply [this patch](https://github.com/intel/linux-sgx-driver/pull/133/commits/ed2c256929962db1a8805db53bed09bb8f2f4de3) then
reload the modified isgx driver to work around the issue.
