# epm

[epm](https://github.com/alibaba/inclavare-containers/tree/master/docs/design/epm/design.md) is a service that is used to manage the cache pools to optimize the startup time of enclave.


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

The Configuration file of epm must be placed into `/etc/epm/config.toml`

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
/bin/bash /usr/local/bin/epm --config=/etc/epm/config.toml --stderrthreshold=0
```

## Third Party Dependencies

Direct Dependencies

| Name | Repo URL | Licenses |
| :--: | :-------:   | :-------: |
| toml | github.com/BurntSushi/toml | MIT |
| bolt | github.com/boltdb/bolt | MIT |
| testify | github.com/stretchr/testify | MIT |
| logrus | github.com/sirupsen/logrus | MIT |
| glog | github.com/golang/glog | Apache-2.0 |
| grpc | github.com/grpc-ecosystem/go-grpc-prometheus | Apache-2.0 |
| cobra | github.com/spf13/cobra | Apache-2.0 |
| grpc | google.golang.org/grpc | Apache-2.0 |
| protobuf | google.golang.org/protobuf | BSD-3-Clause |
| pflag | github.com/spf13/pflag | BSD-3-Clause |
| protobuf | github.com/golang/protobuf | BSD-3-Clause |
| sys | golang.org/x/sys | BSD-3-Clause |
