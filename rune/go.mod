module github.com/inclavare-containers/rune

go 1.14

require (
	github.com/checkpoint-restore/go-criu v0.0.0-20191125063657-fcdcd07065c5 // indirect
	github.com/checkpoint-restore/go-criu/v5 v5.0.0
	github.com/cilium/ebpf v0.6.2 // indirect
	github.com/containerd/console v1.0.2
	github.com/coreos/go-systemd/v22 v22.3.2
	github.com/cyphar/filepath-securejoin v0.2.3
	github.com/docker/go-units v0.4.0
	github.com/go-restruct/restruct v0.0.0-20191227155143-5734170a48a1
	github.com/golang/protobuf v1.5.0
	github.com/inclavare-containers/epm v0.0.0-00010101000000-000000000000
	github.com/moby/sys/mountinfo v0.4.1
	github.com/mrunalp/fileutils v0.5.0
	github.com/opencontainers/runc v1.0.3
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/opencontainers/selinux v1.8.2
	github.com/pkg/errors v0.9.1
	github.com/prometheus/procfs v0.2.0
	github.com/sirupsen/logrus v1.8.1
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635 // indirect
	// NOTE: urfave/cli must be <= v1.22.1 due to a regression: https://github.com/urfave/cli/issues/1092
	github.com/urfave/cli v1.22.1
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b
	golang.org/x/sys v0.0.0-20210426230700-d19ff857e887
	google.golang.org/grpc v1.33.1
	google.golang.org/protobuf v1.27.1
)

replace github.com/inclavare-containers/epm => github.com/alibaba/inclavare-containers/epm v0.0.0-20210702020106-e5fad0ed1646
