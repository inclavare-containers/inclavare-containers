# Building

Please follow the command to build Enclave TLS from the latested source code on your system.

1. Download the latest source code of Enclave TLS

```shell
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"
git clone https://github.com/alibaba/inclavare-containers -b enclave-tls
```

2. Build and install Enclave TLS

```shell
cd inclavare-containers/enclave-tls
make && make install
```

{enclave-tls-server,enclave-tls-client} will be installed to /opt/enclave-tls/bin/{enclave-tls-server,enclave-tls-client} on your system.

# RUN

Right now, Enclave TLS supports the following instance types:

| Priority | Tls Wrapper instances | Encalve Quote instances | Crypto Wrapper Instance |
| -------- | --------------------- | ----------------------- | ----------------------- |
| low      | Nulltls               | Null                    | Null                    |
| Medium   | Wolfssl               | Sgx-ecdsa               | Wolfcrypt               |
| High     | Wolfs-sgx             |                         |                         |

By default,  Enclave TLS will select the highest priority instance to work.

## Run enclave tls server
```
cd /opt/enclave-tls/bin
./enclave-tls-server run
```

## Run enclave tls client
```
cd /opt/enclave-tls/bin
./enclave-tls-client echo
```

## Specify the instance type

The options of enclave-tls-server are as followed:  
Please type `./enclave-tls-client echo --help` to see the options of enclave-tls-client

```
OPTIONS:
   --addr value       the server address
   --log-level value  set the level of log output
   --attester value   set he type of quote attester
   --verifier value   set the type of quote verifier
   --tls value        set the type of tls wrapper
   --crypto value     set the type of crypto wrapper
```

You can set command line parameters to specify different configurations.

For example:
```
./enclave-tls-server run  --tls wolfssl
./enclave-tls-server run  --tls wolfssl_sgx
./enclave-tls-server run  --attester sgx_ecdsa
./enclave-tls-server run  --crypto wolfcrypt
```
