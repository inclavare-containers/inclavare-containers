module github.com/inclavare-containers/shim

go 1.13

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/containerd/cgroups v1.0.1
	github.com/containerd/containerd v1.5.4
	github.com/containerd/go-runc v1.0.0
	github.com/containerd/typeurl v1.0.2
	github.com/coreos/go-systemd/v22 v22.3.2 // indirect
	github.com/gin-gonic/gin v1.7.0
	github.com/gogo/protobuf v1.3.2
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/inclavare-containers/epm v0.0.0-00010101000000-000000000000
	github.com/opencontainers/runc v1.0.1 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.6.1
	golang.org/x/sys v0.0.0-20210426230700-d19ff857e887
	google.golang.org/grpc v1.33.2
	google.golang.org/protobuf v1.27.1 // indirect
	k8s.io/apimachinery v0.20.6
	k8s.io/klog/v2 v2.4.0

)

replace (
	github.com/docker/distribution => github.com/docker/distribution v2.7.1-0.20190205005809-0d3efadf0154+incompatible
	github.com/inclavare-containers/epm => ../epm
	github.com/inclavare-containers/rune => ../rune
	github.com/opencontainers/runc => github.com/opencontainers/runc v0.0.0-20200429033603-85c44b190e42

)
