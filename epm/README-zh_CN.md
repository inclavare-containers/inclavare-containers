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

The Configuration file of epm MUST BE placed into `/etc/epm/config.toml`

```toml
root = "/var/local/epm"

[grpc]
  address = "/var/run/epm/epm.sock"
  uid = 0
  gid = 0
  max_recv_message_size = 16777216
  max_send_message_size = 16777216

[cache_pools]
  [cache_pools.bundle-cache-pool_occlum_cache0]
    type = "bundle-cache-pool.occlum.cache0"
  [cache_pools.bundle-cache-pool_occlum_cache1]
    type = "bundle-cache-pool.occlum.cache1"
  [cache_pools.bundle-cache-pool_occlum_cache2]
    type = "bundle-cache-pool.occlum.cache2"
```

## Run the epm
```bash
/bin/bash /usr/local/bin/epm
```
