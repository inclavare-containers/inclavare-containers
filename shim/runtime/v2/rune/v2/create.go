package v2

import (
	"context"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/runtime/v2/runc"
	taskAPI "github.com/containerd/containerd/runtime/v2/task"
	"github.com/inclavare-containers/shim/runtime/v2/rune/oci"
	shim_types "github.com/inclavare-containers/shim/runtime/v2/rune/types"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/compatoci"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func create(ctx context.Context, s *service, r *taskAPI.CreateTaskRequest) (*runc.Container, error) {
	ociSpec, _, err := loadSpec(r.ID, r.Bundle)
	if err != nil {
		return nil, err
	}
	containerType, err := oci.ContainerType(*ociSpec)
	if err != nil {
		return nil, err
	}

	container, err := runc.NewContainer(ctx, s.platform, r)
	if err != nil {
		return nil, err
	}

	switch containerType {
	case shim_types.PodSandbox:
		sandboxNamspace, err := oci.SandboxNamespace(*ociSpec)
		if err != nil {
			return nil, err
		}

		if sandboxNamspace != shim_types.KubeSystem {
			ar := &taskAPI.CreateTaskRequest{
				ID:       generateID(),
				Terminal: false,
				Options:  r.Options,
			}

			// Create agent enclave container
			agentContainer, err := createAgentContainer(ctx, s, ar)
			if err != nil {
				return nil, err
			}

			if err := writeAgentIdFile(r.Bundle, ar.ID); err != nil {
				return nil, err
			}

			s.agentID = ar.ID
			s.puaseID = r.ID
			s.containers[ar.ID] = agentContainer
		}
	}

	return container, nil
}

func loadSpec(id string, bundle string) (*specs.Spec, string, error) {
	// Checks the MUST and MUST NOT from OCI runtime specification
	bundlePath, err := validBundle(id, bundle)
	if err != nil {
		return nil, "", err
	}

	ociSpec, err := compatoci.ParseConfigJSON(bundlePath)
	if err != nil {
		return nil, "", err
	}

	return &ociSpec, bundlePath, nil
}

// ReadAgentIdFile reads the agent container id information from the path
func readAgentIdFile(path string) (string, error) {
	data, err := os.ReadFile(filepath.Join(path, "agent.id"))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// WriteAgentIdFile writes the agent container id information into the path
func writeAgentIdFile(path, id string) error {
	return os.WriteFile(filepath.Join(path, "agent.id"), []byte(id), 0600)
}
