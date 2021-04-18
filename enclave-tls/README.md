# Building

Please follow the command to build Enclave TLS from the latested source code on your system.

1. Download the latest source code of Enclave TLS

```shell
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"
git clone https://github.com/alibaba/inclavare-containers
```

2. Build and install Enclave TLS

```shell
cd inclavare-containers/enclave-tls
make
make install
```

`{enclave-tls-server,enclave-tls-client}` will be installed to `/opt/enclave-tls/bin/{enclave-tls-server,enclave-tls-client}` on your system. All instances are placed in `/opt/enclave-tls/lib`.

If you want to build instances related to sgx(wolfssl\_sgx, sgx\_ecdsa, sgx\_la, wolfcrypt\_sgx), please type the following command.

```shell
make SGX=1
```

# RUN

Right now, Enclave TLS supports the following instance types:

| Priority | Tls Wrapper instances | Encalve Quote instances | Crypto Wrapper Instance |
| -------- | --------------------- | ----------------------- | ----------------------- |
| low      | nulltls               | nullquote               | nullcrypto              |
| Medium   | wolfssl               | sgx\_ecdsa              | wolfcrypt               |
| High     | wolfssl\_sgx          | sgx\_la                 | wolfcrypt\_sgx          |

By default,  Enclave TLS will select the **highest priority** instance to use.

## Run enclave tls server
```
cd /opt/enclave-tls/bin
./enclave-tls-server
```

## Run enclave tls client
```
cd /opt/enclave-tls/bin
./enclave-tls-client
```

## Specify the instance type

The options of enclave-tls-server are as followed:  

```shell
OPTIONS:
   --attester/-a value   set he type of quote attester
   --verifier/-v value   set the type of quote verifier
   --tls/-t value        set the type of tls wrapper
   --crypto/-c value     set the type of crypto wrapper
   --mutual/-m           set to enable mutual attestation
```

You can set command line parameters to specify different configurations.

For example:

```shell
./enclave-tls-server --tls wolfssl
./enclave-tls-server --tls wolfssl_sgx
./enclave-tls-server --attester sgx_ecdsa
./enclave-tls-server --attester sgx_la
./enclave-tls-server run  --crypto wolfcrypt
```

## Mutual attestation

You can use `-m` option to enable mutual attestation.

```shell
./enclave-tls-server -m
./enclave-tls-client -m
```

# Deployment

## Occlum LibOS

Please refer to [this guide](docs/run_enclave_tls_with_occlum.md) to run Enclave Tls with [Occlum](https://github.com/occlum/occlum) and [rune](https://github.com/alibaba/inclavare-containers/tree/master/rune).
