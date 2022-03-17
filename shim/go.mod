module github.com/inclavare-containers/shim

go 1.13

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/Microsoft/go-winio v0.4.17 // indirect
	github.com/Microsoft/hcsshim v0.8.23 // indirect
	github.com/Microsoft/hcsshim/test v0.0.0-20220316062654-cf6b2c91e41a // indirect
	github.com/containerd/aufs v1.0.0 // indirect
	github.com/containerd/btrfs v1.0.0 // indirect
	github.com/containerd/cgroups v1.0.1
	github.com/containerd/console v1.0.2 // indirect
	github.com/containerd/containerd v1.5.10
	github.com/containerd/continuity v0.1.0 // indirect
	github.com/containerd/cri v1.19.0 // indirect
	github.com/containerd/fifo v1.0.0 // indirect
	github.com/containerd/go-runc v1.0.0
	github.com/containerd/ttrpc v1.1.0 // indirect
	github.com/containerd/typeurl v1.0.2
	github.com/containerd/zfs v1.0.0 // indirect
	github.com/coreos/go-systemd/v22 v22.3.2 // indirect
	github.com/docker/docker v20.10.13+incompatible // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-metrics v0.0.1 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/gin-gonic/gin v1.7.0
	github.com/gogo/googleapis v1.4.0 // indirect
	github.com/gogo/protobuf v1.3.2
	github.com/google/go-cmp v0.5.5 // indirect
	github.com/google/uuid v1.2.0 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inclavare-containers/epm v0.0.0-00010101000000-000000000000
	github.com/kr/pretty v0.2.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/opencontainers/runc v1.0.3 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/opencontainers/selinux v1.8.2 // indirect
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.7.1 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.2.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635 // indirect
	github.com/urfave/cli v1.22.2 // indirect
	go.etcd.io/bbolt v1.3.5 // indirect
	golang.org/x/net v0.0.0-20210405180319-a5a99cb37ef4 // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e
	google.golang.org/grpc v1.40.0
	google.golang.org/protobuf v1.27.1 // indirect
	gotest.tools/v3 v3.1.0 // indirect
	k8s.io/apimachinery v0.20.6
	k8s.io/klog v1.0.0 // indirect
	k8s.io/klog/v2 v2.4.0
	sigs.k8s.io/structured-merge-diff/v3 v3.0.0 // indirect

)

replace (
	github.com/docker/distribution => github.com/docker/distribution v0.0.0-20220207154021-dcf66392d606
	github.com/inclavare-containers/epm => ../epm
	github.com/inclavare-containers/rune => ../rune

)
