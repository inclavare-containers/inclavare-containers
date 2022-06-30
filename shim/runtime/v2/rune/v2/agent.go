package v2

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/BurntSushi/toml"
	types "github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/pkg/process"
	"github.com/containerd/containerd/runtime/v2/runc"
	taskAPI "github.com/containerd/containerd/runtime/v2/task"
	"github.com/containerd/continuity/fs"
	runcC "github.com/containerd/go-runc"
	shim_config "github.com/inclavare-containers/shim/config"
	"github.com/inclavare-containers/shim/runtime/v2/rune/constants"
	"github.com/sirupsen/logrus"
)

func createAgentContainer(ctx context.Context, s *service, r *taskAPI.CreateTaskRequest) (*runc.Container, error) {
	dir := filepath.Join(agentContainerRootDir, r.ID)
	upperDir := path.Join(dir, "upper")
	workDir := path.Join(dir, "work")
	destDir := path.Join(dir, "merged")
	for _, dir := range []string{upperDir, workDir, destDir} {
		if err := os.MkdirAll(dir, 0711); err != nil && !os.IsExist(err) {
			return nil, err
		}
	}

	var options []string
	// Set index=off when mount overlayfs
	options = append(options, "index=off")
	options = append(options,
		fmt.Sprintf("lowerdir=%s", filepath.Join(agentContainerPath, "rootfs")),
		fmt.Sprintf("workdir=%s", workDir),
		fmt.Sprintf("upperdir=%s", upperDir),
	)
	r.Rootfs = append(r.Rootfs, &types.Mount{
		Type:    "overlay",
		Source:  "overlay",
		Options: options,
	})
	r.Bundle = destDir

	fs.CopyFile(filepath.Join(r.Bundle, "config.json"), filepath.Join(agentContainerPath, "config.json"))

	// Create Stdout and Stderr file for agent enclave container
	r.Stdout = filepath.Join(agentContainerRootDir, r.ID, r.ID+"-stdout")
	r.Stderr = filepath.Join(agentContainerRootDir, r.ID, r.ID+"-stderr")
	for _, file := range []string{r.Stdout, r.Stderr} {
		f, err := os.Create(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
	}

	agentContainer, err := runc.NewContainer(ctx, s.platform, r)
	if err != nil {
		return nil, err
	}

	return agentContainer, nil
}

// Cleanup the agent enclave container resource
func cleanupAgentContainer(ctx context.Context, id string) error {
	var cfg shim_config.Config
	if _, err := toml.DecodeFile(constants.ConfigurationPath, &cfg); err != nil {
		return err
	}
	rootdir := cfg.Containerd.AgentContainerRootDir
	path := filepath.Join(rootdir, id, "merged")

	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return err
	}
	runtime, err := runc.ReadRuntime(path)
	if err != nil {
		return err
	}
	opts, err := runc.ReadOptions(path)
	if err != nil {
		return err
	}
	root := process.RuncRoot
	if opts != nil && opts.Root != "" {
		root = opts.Root
	}

	shimLog.WithFields(logrus.Fields{
		"root":    root,
		"path":    path,
		"ns":      ns,
		"runtime": runtime,
	}).Debug("agent enclave Container Cleanup()")

	r := process.NewRunc(root, path, ns, runtime, "", false)
	if err := r.Delete(ctx, id, &runcC.DeleteOpts{
		Force: true,
	}); err != nil {
		logrus.WithError(err).Warn("failed to remove runc agent enclave container")
	}
	if err := mount.UnmountAll(filepath.Join(path, "rootfs"), 0); err != nil {
		logrus.WithError(err).Warn("failed to cleanup rootfs mount")
	}
	if err := os.RemoveAll(filepath.Join(rootdir, id)); err != nil {
		logrus.WithError(err).Warn("failed to remove agent enclave container path")
	}

	return nil
}
