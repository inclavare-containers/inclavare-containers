module github.com/inclavare-containers/shim

go 1.13

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/containerd/cgroups v1.0.3
	github.com/containerd/containerd v1.5.13
	github.com/containerd/go-runc v1.0.0
	github.com/containerd/typeurl v1.0.2
	github.com/gin-gonic/gin v1.7.0
	github.com/gogo/protobuf v1.3.2
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/inclavare-containers/epm v0.0.0-00010101000000-000000000000
	github.com/opencontainers/runc v1.0.3 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.2.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	golang.org/x/sys v0.0.0-20220412211240-33da011f77ad
	google.golang.org/grpc v1.40.0
	gotest.tools/v3 v3.1.0 // indirect
	k8s.io/apimachinery v0.20.6
	k8s.io/klog/v2 v2.4.0

)

replace (
	github.com/docker/distribution => github.com/docker/distribution v0.0.0-20220207154021-dcf66392d606
	github.com/inclavare-containers/epm => ../epm
	github.com/inclavare-containers/rune => ../rune

)
