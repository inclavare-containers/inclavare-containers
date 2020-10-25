module github.com/inclavare-containers/rune

go 1.14

require (
	github.com/checkpoint-restore/go-criu v0.0.0-20191125063657-fcdcd07065c5
	github.com/containerd/console v1.0.0
	github.com/coreos/go-systemd/v22 v22.0.0
	github.com/cyphar/filepath-securejoin v0.2.2
	github.com/docker/go-units v0.4.0
	github.com/go-restruct/restruct v0.0.0-20191227155143-5734170a48a1
	github.com/golang/protobuf v1.3.5
	github.com/moby/sys/mountinfo v0.1.3
	github.com/mrunalp/fileutils v0.0.0-20171103030105-7d4729fb3618
	github.com/opencontainers/runc v0.0.0-20200429033603-85c44b190e42
	github.com/opencontainers/runtime-spec v1.0.2
	github.com/opencontainers/selinux v1.4.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.5.0
	github.com/syndtr/gocapability v0.0.0-20180916011248-d98352740cb2
	// NOTE: urfave/cli must be <= v1.22.1 due to a regression: https://github.com/urfave/cli/issues/1092
	github.com/urfave/cli v1.22.1
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/sys v0.0.0-20200327173247-9dae0f8f5775
)
