# epm

epm is a service that is used to manage the cache pools to optimize the startup time of enclave.


## Build requirements

Go 1.13.x or above.

## How to build and install

### Step 1: Build and install epm binary.
```bash
mkdir -p $GOPATH/src/github.com/alibaba
cd $GOPATH/src/github.com/alibaba 
git clone https://github.com/alibaba/inclavare-containers.git

cd epm
GOOS=linux make binaries
make install
ls -l /usr/local/bin/epm
```

### Step 2: Configuration

The Configuration file of epm must be placed into `/var/run/epm/config.toml`

```toml
root = "/var/local/epm"
db_path = "/etc/epm/epm.db"
db_timeout = 10

[grpc]
  address = "/var/run/epm/epm.sock"
  uid = 0
  gid = 0
  max_recv_message_size = 16777216
  max_send_message_size = 16777216
```

## Run the epm
```bash
/bin/bash /usr/local/bin/epm --config=/var/run/epm/config.toml --stderrthreshold=0
```
