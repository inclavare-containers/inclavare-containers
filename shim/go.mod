module github.com/inclavare-containers/shim

go 1.13

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/Microsoft/go-winio v0.4.16 // indirect
	github.com/Microsoft/hcsshim v0.8.14 // indirect
	github.com/containerd/cgroups v0.0.0-20200531161412-0dbf7f05ba59
	github.com/containerd/console v1.0.2 // indirect
	github.com/containerd/containerd v1.4.12
	github.com/containerd/continuity v0.0.0-20201208142359-180525291bb7 // indirect
	github.com/containerd/fifo v0.0.0-20201026212402-0724c46b320c // indirect
	github.com/containerd/go-runc v0.0.0-20200220073739-7016d3ce2328
	github.com/containerd/ttrpc v1.0.2 // indirect
	github.com/containerd/typeurl v1.0.0
	github.com/coreos/go-systemd/v22 v22.3.2 // indirect
	github.com/docker/distribution v0.0.0-00010101000000-000000000000 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/gin-gonic/gin v1.7.0
	github.com/gogo/googleapis v1.4.0 // indirect
	github.com/gogo/protobuf v1.3.2
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/imdario/mergo v0.3.11 // indirect
	github.com/inclavare-containers/epm v0.0.0-00010101000000-000000000000
	github.com/kr/pretty v0.2.1 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/opencontainers/runc v1.0.3 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/pkg/errors v0.9.1
	github.com/prometheus/procfs v0.2.0 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.2.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635 // indirect
	golang.org/x/sys v0.0.0-20210510120138-977fb7262007
	google.golang.org/grpc v1.38.0
	google.golang.org/protobuf v1.27.1 // indirect
	k8s.io/apimachinery v0.18.2
	k8s.io/klog/v2 v2.4.0

)

replace (
	github.com/docker/distribution => github.com/docker/distribution v2.7.1-0.20190205005809-0d3efadf0154+incompatible
	github.com/inclavare-containers/epm => ../epm
	github.com/inclavare-containers/rune => ../rune

)
