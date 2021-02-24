# Introduction
This guide will guide you how to use remote attestation based on SGX in skeleton with rune. **Currently `rune attest` can only run on the machines with [OOT SGX dirver](https://github.com/intel/linux-sgx-driver), we will support [DCAP driver](https://github.com/intel/SGXDataCenterAttestationPrimitives) as soon as possible**.

# Before you start
- Build a skeleton bundle according to [this guide](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/skeleton/README.md) from scratch.
- Build rune according to [this guide](https://github.com/alibaba/inclavare-containers#rune).
- Register a `SPID` and `Subscription Key` of [IAS](https://api.portal.trustedservices.intel.com/EPID-attestation) to get IAS report(optional). After the registration, Intel will respond with a SPID which is needed to communicate with IAS.

# Configure skeleton bundle
- Before using `rune attest` command, you must ensure your skeleton container/bundles(such as skeleton-enclave-container) running by setting `"wait_timeout","100"` of `process.args` in config.json as following:
```json
"process": {
	"args": [
		"${YOUR_PROGRAM}","wait_timeout","100"
	],
}
```

- Only `liberpal-skeleton-v3.so` supports `rune attest` command. So you also need to configure enclave runtime as following:
```json
"annotations": {
      "enclave.type": "intelSgx",
      "enclave.runtime.path": "/usr/lib/liberpal-skeleton-v3.so",
      "enclave.runtime.args": "debug"
}
```

- If you want to use `rune attest` command to get IAS report, you also need to **`delete`** the `network` namespace configuration in your `config.json` to ensure you run skeleton in host network mode. After doing this, your `namespaces` is as following without the `network` type namespace:
```json
                "namespaces": [
                        {
                                "type": "pid"
                        },
                        {
                                "type": "ipc"
                        },
                        {
                                "type": "uts"
                        },
                        {
                                "type": "mount"
                        }
                ],
```

# Run skeleton bundle with `rune`
Then you can run your skeleton containers by typing the following commands:

```shell
cd "$HOME/rune_workdir/rune-container"

# copy /etc/resolv.conf from host to bundles to ensure network is ready for getting IAS report.
cp /etc/resolv.conf rootfs/etc/resolv.conf

sudo rune --debug run skeleton-enclave-container
```

# Use `rune attest` command with skeleton
## Get local report

You can type the following command to use `rune attest` command with skeleton in another shell to get local report:
```shell
rune --debug attest --quote-type={SGX_QUOTE_TYPE} skeleton-enclave-container
```

where:
- @quote-type: specify the quote types of sgx, such as,
	- `epidUnlinkable`: [epid for unlinkable](https://api.portal.trustedservices.intel.com/EPID-attestation)
	- `epidLinkable`: [epid for linkable](https://api.portal.trustedservices.intel.com/EPID-attestation)
	- `ecdsa`: [ECDSA](https://github.com/intel/linux-sgx#ecdsa-attestation). **Note `rune attest` currently doesn't support the ecdsa quote type, and we will support it soon**.


## Get IAS report

You can type the following command to use `rune attest` command with skeleton in another shell to get IAS report:

```shell
rune --debug attest --isRA \
		--quote-type={SGX_QUOTE_TYPE} \
		--spid=${EPID_SPID} \
		--subscription-key=${EPID_SUBSCRIPTION_KEY} \
		skeleton-enclave-container
```

where:
- @isRA: specify the type of report is local or remote report.
- @quote-type: specify the quote types of sgx which is the same as the parameters of [Get local report](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/skeleton/running_skeleton_with_rune_attest_command.md#get-local-report).
- @spid: specify the `SPID`.
- @subscription-key: specify the `Subscription Key`.
