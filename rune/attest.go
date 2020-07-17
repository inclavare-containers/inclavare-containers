package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/utils"
	_ "github.com/opencontainers/runc/libenclave/attestation/sgx/ias"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"
)

const (
	envSeparator = "="
)

var attestCommand = cli.Command{
	Name:  "attest",
	Usage: "attest generates a remote attestation to the corresponding enclave container",
	ArgsUsage: `<container-id> [command options]
Where "<container-id>" is the name for the instance of the container`,
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "product",
			Usage: "specify whether using production attestation service",
		},
		cli.StringFlag{
			Name:  "spid",
			Usage: "specify SPID",
		},
		cli.StringFlag{
			Name:  "subscription-key, -key",
			Usage: "specify the subscription key",
		},
		cli.BoolFlag{
			Name:  "linkable",
			Usage: "specify the EPID signatures policy type",
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

	config := container.Config()
	if config.Enclave == nil {
		return -1, fmt.Errorf("Attest command: container.Config.Enclave is null")
	}

	state, err := container.State()
	if err != nil {
		return -1, err
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
	p.Env = append(p.Env, fmt.Sprintf("%s%s%s", "SPID", envSeparator, context.String("spid")))
	p.Env = append(p.Env, fmt.Sprintf("%s%s%s", "SUBSCRIPTION_KEY", envSeparator, context.String("subscription-key")))
	p.Env = append(p.Env, fmt.Sprintf("%s%s%s", "PRODUCT", envSeparator, context.Bool("product")))

	var quote_type string = "SGX_UNLINKABLE_SIGNATURE"
	if context.Bool("linkable") {
		quote_type = "SGX_LINKABLE_SIGNATURE"
	}
	p.Env = append(p.Env, fmt.Sprintf("%s%s%s", "QUOTE_TYPE", envSeparator, quote_type))

	var AttestCommand bool = true
	p.Env = append(p.Env, fmt.Sprintf("%s%s%d", "AttestCommand", envSeparator, AttestCommand))

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
