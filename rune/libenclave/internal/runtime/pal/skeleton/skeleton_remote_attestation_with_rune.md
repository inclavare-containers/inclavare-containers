# Introduction
This guide will guide you how to use remote attestation based on SGX in skeleton with rune.

# Before you start
- Build a skeleton bundle according to [this guide](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/skeleton/README.md) from scratch.
- Build rune according to [this guide](https://github.com/alibaba/inclavare-containers#rune).
- Register a `SPID` and `Subscription Key` of [IAS](https://api.portal.trustedservices.intel.com/EPID-attestation). After the registration, Intel will respond with a SPID which is needed to communicate with IAS.

# Enable Remote Attestation when skeleton starts
 You need to configure enclave runtime as following:
```json
"annotations": {
	"enclave.type": "intelSgx",
	"enclave.runtime.path": "/usr/lib/liberpal-skeleton.so",
	"enclave.runtime.args": "debug,attest-test",
	"enclave.attestation.ra_type": "EPID",
	"enclave.is_product_enclave": "false",
	"enclave.attestation.ra_epid_spid": "${EPID_SPID}",
	"enclave.attestation.ra_epid_subscription_key": "${EPID_SUBSCRIPTION_KEY}",
	"enclave.attestation.ra_epid_is_linkable": "false"
}
```

where:
- @enclave.type: specify the type of enclave hardware to use, such as `intelSgx`.
- @enclave.runtime.path: specify the path to enclave runtime to launch.
- @enclave.runtime.args: specify the specific arguments to enclave runtime, seperated by the comma.
- @enclave.attestation.ra_type:  specify the type of remote attestation, such as `EPID`(recommended) or `DCAP`(not supported by `IAS` now). If `not` set this value,  Remote Attestation is `disable` when skeleton starting.
- @enclave.is_product_enclave: specify the type of enclave is in product mode or debug mode.
- @enclave.attestation.ra_epid_spid: specify the `SPID`.
- @enclave.attestation.ra_epid_subscription_key: specify the `Subscription Key`.
- @enclave.attestation.ra_epid_is_linkable: specify the type of `EPID` is `linkable` or `unlinkable`.  

then you can type the following command to run skeleton:

```shell
cd "$HOME/rune_workdir/rune-container"

# copy /etc/resolv.conf from host to bundles to ensure network is ready for the remote attestation of IAS.
cp /etc/resolv.conf rootfs/etc/resolv.conf

sudo rune run skeleton-enclave-container
```

# Use `rune attest` command with skeleton
Before using `rune attest` command, you must ensure your skeleton container(such as skeleton-enclave-container) running by setting `"enclave.runtime.args": "attest-test"` in config.json.
```json
"annotations": {
        "enclave.runtime.args": "attest-test"
}
```

You can type the following command to use `rune attest` command with skeleton:

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
