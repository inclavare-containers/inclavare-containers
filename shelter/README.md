# shelter

Shelter is designed as a remote attestation tool for customer to verify if their workloads are loaded in a specified intel authorized sgx enclaved.

The verifying process is as below:
1. shelter setup a security channel based on mTLS with inclavared
2. inclavared will generate/retrieve the quote info of workload running enclave
3. inclavared will get IAS report by quote info from Intel authorized web server
4. inclavared will generate attestation verification report
5. shelter will verify the attestation verification report and mrenclave value by mTLS security channel
6. shelter will report the verifying result

## Prerequisite

Go 1.14.x or above.

## Build

Please follow the command to build Inclavare Containers from the latested source code on your system.

1. Download the latest source code of Inclavare Containers

```shell
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"
git clone https://github.com/alibaba/inclavare-containers
```

2. Prepare the dependence libs required by shelter

### Build and install enclave-tls

Please follow [enclave-tls README](https://github.com/alibaba/inclavare-containers/tree/master/enclave-tls) to build and install enclave-tls firstly.

### For EPID RA

```shell
cd $WORKSPACE/inclavare-containers/shelter
make
```

### For DCAP RA

1. Please refer to [this guide](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/README.md) to install DCAP. Note: If your platform is pre-product SGX platform (SBX), please follow this guide to resolve the quote verification problem on SBX platforms: https://github.com/alibaba/inclavare-containers/blob/master/hack/use-sbx-platform/README.md.
2. Please refer to [this guide](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteGeneration/pccs) to install and configure Intel PCCS service to make sure Intel PCCS to be luanched correctly.

```shell
cd $WORKSPACE/inclavare-containers/shelter
make 
```

## Run

Before running shelter, make sure inclavared being luanched as server mode successfully in the same machine.
You can find the way to run inclavared by: https://github.com/alibaba/inclavare-containers/inclavared

1. check shelter support feature as below

```shell
shelter help
   NAME:
      shelter - shelter as a remote attestation tool for workload runing in enclave containers.

   USAGE:
      shelter [global options] command [command options] [arguments...]

   VERSION:
      0.0.1

   COMMANDS:
      remoteattestation  attest IAS report obtained by inclavared and setup TLS security channel with inclavared
      mrverify           download target source code to rebuild and caculate launch measurement based on software algorithm and then compare with launch measurement in sigsturct file
      help, h            Shows a list of commands or help for one command

   GLOBAL OPTIONS:
      --verbose      enable verbose output
      --help, -h     show help
      --version, -v  print the version
```

2. remote attestation for sgx-ra, sgx-la, and sgx-ecdsa

```shell
OPTIONS:
   --ip             tcp socket ip to connect inclavared
   --port           tcp socket port to connect inclavared
   --log-level      set the level of log output(debug, info, warn, error, fatal, off)
   --verifier       set the type of quote verifier(nullquote, sgx_la or sgx_ecdsa)
   --tls            set the type of tls wrapper(nulltls, wolfssl or wolfssl_sgx)
   --crypto         set the type of crypto wrapper(nullcrypto, wolfcrypt or wolfcrypt_sgx)
   --mutual         set to enable mutual attestation(True, False)
```

You can set command line parameters to specify different configurations.

For example:
```shell
shelter remoteattestation --ip 127.0.0.1 --port 1234
shelter remoteattestation --tls wolfssl
shelter remoteattestation --tls wolfssl_sgx
shelter remoteattestation --verifier sgx_ecdsa
shelter remoteattestation --verifier sgx_la
shelter remoteattestation --crypto wolfcrypt
```

3. verify workload integrity by launch measurement.
   The software algorithm refer to [skeleton](https://github.com/alibaba/inclavare-containers/tree/master/rune/libenclave/internal/runtime/pal/skeleton) project.

```shell
shelter mrverify
```

## Touble shooting

TODO
