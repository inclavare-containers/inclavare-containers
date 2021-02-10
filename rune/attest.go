package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"github.com/inclavare-containers/rune/libenclave"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"
)

const (
	envSeparator = "="
)

var attestCommand = cli.Command{
	Name:  "attest",
	Usage: "attest gets the remote or local report to the corresponding enclave container",
	ArgsUsage: `<container-id> [command options]
Where "<container-id>" is the name for the instance of the container`,
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "isRA",
			Usage: "specify whether to get the remote or local report",
		},
		cli.StringFlag{
			Name:  "quote-type",
			Usage: "specify the SGX quote type such as epidUnlinkable, epidLinkable and ecdsa",
		},
		cli.StringFlag{
			Name:  "spid",
			Usage: "specify SPID",
		},
		cli.StringFlag{
			Name:  "subscription-key, -key",
			Usage: "specify the subscription key",
		},
		cli.StringFlag{
			Name:  "reportFile",
			Usage: "path to the output report file(in the ${bundle}/rootfs) containing the corresponding REPORT(currently only using to save the local report)",
		},
	},
	Action: func(context *cli.Context) error {
		if err := revisePidFile(context); err != nil {
			return err
		}
		status, err := attestProcess(context)
		if err == nil {
			os.Exit(status)
		}
		return fmt.Errorf("attest failed: %v", err)
	},
	SkipArgReorder: true,
}

func attestProcess(context *cli.Context) (int, error) {
	container, err := getContainer(context)
	if err != nil {
		return -1, err
	}

	status, err := container.Status()
	if err != nil {
		return -1, err
	}
	if status == libcontainer.Stopped {
		return -1, fmt.Errorf("cannot attest a container that has stopped")
	}

	state, err := container.State()
	if err != nil {
		return -1, err
	}

	enclaveState := (*libenclave.EnclaveState)(unsafe.Pointer(state))
	if enclaveState.EnclaveConfig.Enclave == nil {
		return -1, fmt.Errorf("Attest command: container.EnclaveConfig is null")
	}

	bundle := utils.SearchLabels(state.Config.Labels, "bundle")
	p, err := getAttestProcess(context, bundle)
	if err != nil {
		return -1, err
	}

	logLevel := "info"
	if context.GlobalBool("debug") {
		logLevel = "debug"
	}

	r := &runner{
		enableSubreaper: false,
		shouldDestroy:   false,
		container:       container,
		consoleSocket:   context.String("console-socket"),
		detach:          false,
		action:          CT_ACT_RUN,
		init:            false,
		preserveFDs:     context.Int("preserve-fds"),
		logLevel:        logLevel,
	}
	return r.run(p)
}

func getAttestProcess(context *cli.Context, bundle string) (*specs.Process, error) {
	// process via cli flags
	if err := os.Chdir(bundle); err != nil {
		return nil, err
	}
	spec, err := loadSpec(specConfig)
	if err != nil {
		return nil, err
	}
	p := spec.Process
	p.Args = context.Args()[1:]
	// override the cwd, if passed
	if context.String("cwd") != "" {
		p.Cwd = context.String("cwd")
	}
	if ap := context.String("apparmor"); ap != "" {
		p.ApparmorProfile = ap
	}
	if l := context.String("process-label"); l != "" {
		p.SelinuxLabel = l
	}
	if caps := context.StringSlice("cap"); len(caps) > 0 {
		for _, c := range caps {
			p.Capabilities.Bounding = append(p.Capabilities.Bounding, c)
			p.Capabilities.Inheritable = append(p.Capabilities.Inheritable, c)
			p.Capabilities.Effective = append(p.Capabilities.Effective, c)
			p.Capabilities.Permitted = append(p.Capabilities.Permitted, c)
			p.Capabilities.Ambient = append(p.Capabilities.Ambient, c)
		}
	}
	// append the passed env variables
	isRemoteAttestation := "false"
	if context.Bool("isRA") {
		isRemoteAttestation = "true"
	}
	p.Env = append(p.Env, "IsRemoteAttestation"+envSeparator+isRemoteAttestation)

	p.Env = append(p.Env, "QUOTE_TYPE"+envSeparator+context.String("quote-type"))
	p.Env = append(p.Env, "SPID"+envSeparator+context.String("spid"))
	p.Env = append(p.Env, "SUBSCRIPTION_KEY"+envSeparator+context.String("subscription-key"))
	p.Env = append(p.Env, "REPORT_FILE"+envSeparator+context.String("reportFile"))

	var AttestCommand string = "true"
	p.Env = append(p.Env, "AttestCommand"+envSeparator+AttestCommand)

	// set the tty
	p.Terminal = false
	if context.IsSet("tty") {
		p.Terminal = context.Bool("tty")
	}
	if context.IsSet("no-new-privs") {
		p.NoNewPrivileges = context.Bool("no-new-privs")
	}
	// override the user, if passed
	if context.String("user") != "" {
		u := strings.SplitN(context.String("user"), ":", 2)
		if len(u) > 1 {
			gid, err := strconv.Atoi(u[1])
			if err != nil {
				return nil, fmt.Errorf("parsing %s as int for gid failed: %v", u[1], err)
			}
			p.User.GID = uint32(gid)
		}
		uid, err := strconv.Atoi(u[0])
		if err != nil {
			return nil, fmt.Errorf("parsing %s as int for uid failed: %v", u[0], err)
		}
		p.User.UID = uint32(uid)
	}
	for _, gid := range context.Int64Slice("additional-gids") {
		if gid < 0 {
			return nil, fmt.Errorf("additional-gids must be a positive number %d", gid)
		}
		p.User.AdditionalGids = append(p.User.AdditionalGids, uint32(gid))
	}
	return p, validateAttestProcessSpec(p)
}
