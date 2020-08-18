# Introduction
This guide will guide you how to use remote attestation based on SGX in skeleton with rune.

# Before you start
- Build a skeleton bundle according to [this guide](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/skeleton/README.md) from scratch.
- Build rune according to [this guide](https://github.com/alibaba/inclavare-containers#rune).
- Register a `SPID` and `Subscription Key` of [IAS](https://api.portal.trustedservices.intel.com/EPID-attestation). After the registration, Intel will respond with a SPID which is needed to communicate with IAS.

# Run skeleton bundle with `rune`
Before using `rune attest` command, you must ensure your skeleton container/bundles(such as skeleton-enclave-container) running by setting `"wait_timeout","100"` of `process.args` in config.json, just like
```json
"process": {
	"args": [
		"${YOUR_PROGRAM}","wait_timeout","100"
	],
}
```

Then you can run your skeleton containers by typing the following commands:

```shell
cd "$HOME/rune_workdir/rune-container"

# copy /etc/resolv.conf from host to bundles to ensure network is ready for the remote attestation of IAS.
cp /etc/resolv.conf rootfs/etc/resolv.conf

sudo rune run skeleton-enclave-container
```

# Use `rune attest` command with skeleton
You can type the following command to use `rune attest` command with skeleton in another shell:

```shell
rune attest --product=false \
		--linkable=false \
		--spid=${EPID_SPID} \
		--subscription-key=${EPID_SUBSCRIPTION_KEY} \
		skeleton-enclave-container
```

where:
- @product: specify the type of enclave is in product mode or debug mode.
- @linkable: specify the type of `EPID` is `linkable` or `unlinkable`.
- @spid: specify the `SPID`.
- @subscription-key: specify the `Subscription Key`.
