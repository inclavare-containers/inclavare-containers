module github.com/confidential-containers/enclave-cc/shim

go 1.13

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/containerd/cgroups v1.0.3
	github.com/containerd/containerd v1.6.1
	github.com/containerd/continuity v0.2.2
	github.com/containerd/go-runc v1.0.0
	github.com/containerd/ttrpc v1.1.0
	github.com/containerd/typeurl v1.0.2
	github.com/cri-o/cri-o v1.0.0-rc2.0.20170928185954-3394b3b2d6af
	github.com/gogo/protobuf v1.3.2
	github.com/kata-containers/kata-containers/src/runtime v0.0.0-20220421031749-83979ece18b9
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	golang.org/x/sys v0.0.0-20220204135822-1c1b9b1eba6a
	google.golang.org/grpc v1.43.0
	gotest.tools/v3 v3.1.0 // indirect

)

replace (
	github.com/containerd/containerd => github.com/confidential-containers/containerd v1.6.0-beta.0.0.20220303142103-c8f5e4509dcc
	github.com/docker/distribution => github.com/docker/distribution v0.0.0-20220207154021-dcf66392d606
	google.golang.org/genproto => google.golang.org/genproto v0.0.0-20180817151627-c66870c02cf8
)
