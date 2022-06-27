module github.com/inclavare-containers/shim

go 1.13

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/containerd/cgroups v1.0.3
	github.com/containerd/containerd v1.5.10
	github.com/containerd/go-runc v1.0.0
	github.com/containerd/typeurl v1.0.2
	github.com/gogo/protobuf v1.3.2
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e
	gotest.tools/v3 v3.1.0 // indirect

)

replace (
	github.com/containerd/containerd => github.com/confidential-containers/containerd v1.6.0-beta.0.0.20220303142103-c8f5e4509dcc
	github.com/docker/distribution => github.com/docker/distribution v0.0.0-20220207154021-dcf66392d606
)
