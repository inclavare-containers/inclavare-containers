package v2

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"

	types "github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/runtime/v2/runc"
	taskAPI "github.com/containerd/containerd/runtime/v2/task"
	"github.com/containerd/continuity/fs"
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
