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
rune --debug attest skeleton-enclave-container
```

## Get IAS report

You can type the following command to use `rune attest` command with skeleton in another shell to get IAS report:

```shell
rune --debug attest --isRA \
		--linkable=false \
		--spid=${EPID_SPID} \
		--subscription-key=${EPID_SUBSCRIPTION_KEY} \
		skeleton-enclave-container
```

where:
- @isRA: specify the type of report is local or remote report.
- @linkable: specify the type of `EPID` is `linkable` or `unlinkable`.
- @spid: specify the `SPID`.
- @subscription-key: specify the `Subscription Key`.
