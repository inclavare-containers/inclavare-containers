package oci

import (
	"fmt"

	"github.com/confidential-containers/enclave-cc/shim/runtime/v2/rune/types"
	ctrAnnotations "github.com/containerd/containerd/pkg/cri/annotations"
	crioAnnotations "github.com/cri-o/cri-o/pkg/annotations"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type annotationContainerType struct {
	annotation    string
	containerType types.ContainerType
}

var (
	// CRIContainerTypeKeyList lists all the CRI keys that could define
	// the container type from annotations in the config.json.
	CRIContainerTypeKeyList = []string{ctrAnnotations.ContainerType, crioAnnotations.ContainerType}

	// CRIContainerTypeList lists all the maps from CRI ContainerTypes annotations
	// to a virtcontainers ContainerType.
	CRIContainerTypeList = []annotationContainerType{
		{crioAnnotations.ContainerTypeSandbox, types.PodSandbox},
		{crioAnnotations.ContainerTypeContainer, types.PodContainer},
		{ctrAnnotations.ContainerTypeSandbox, types.PodSandbox},
		{ctrAnnotations.ContainerTypeContainer, types.PodContainer},
	}
)

// ContainerType returns the type of container and if the container type was
// found from CRI server's annotations in the container spec.
func ContainerType(spec specs.Spec) (types.ContainerType, error) {
	for _, key := range CRIContainerTypeKeyList {
		containerTypeVal, ok := spec.Annotations[key]
		if !ok {
			continue
		}

		for _, t := range CRIContainerTypeList {
			if t.annotation == containerTypeVal {
				return t.containerType, nil
			}

		}
		return types.UnknownContainerType, fmt.Errorf("unknown container type %s", containerTypeVal)
	}

	return types.SingleContainer, nil
}

// SandboxNamespaceType returns the namespace of sandbox and if the namespace was
// found from CRI server's annotations in the container spec.
func SandboxNamespace(spec specs.Spec) (string, error) {
	sandboxNamespaceTypeVal, ok := spec.Annotations[ctrAnnotations.SandboxNamespace]
	if !ok {
		return "", fmt.Errorf("unknown sandbox namespace in annotation")
	}

	return sandboxNamespaceTypeVal, nil
}

func GetImage(spec specs.Spec) (string, error) {
	image, ok := spec.Annotations[ctrAnnotations.ImageName]
	if !ok {
		return "", fmt.Errorf("unknown image name in annotation")
	}

	return image, nil
}
