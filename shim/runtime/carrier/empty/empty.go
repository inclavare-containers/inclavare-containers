package empty

import (
	"github.com/alibaba/inclavare-containers/shim/runtime/carrier"
	"github.com/containerd/containerd/runtime/v2/task"
)

var _ carrier.Carrier = &empty{}

type empty struct{}

func NewEmptyCarrier() (carrier.Carrier, error) {
	return &empty{}, nil
}

// Name impl Carrier.
func (c *empty) Name() string {
	return "empty"
}

// BuildUnsignedEnclave impl Carrier.
func (c *empty) BuildUnsignedEnclave(req *task.CreateTaskRequest, args *carrier.BuildUnsignedEnclaveArgs) (
	unsignedEnclave string, err error) {
	return "", nil
}

// GenerateSigningMaterial impl Carrier.
func (c *empty) GenerateSigningMaterial(req *task.CreateTaskRequest, args *carrier.CommonArgs) (
	signingMaterial string, err error) {
	return "", nil
}

// CascadeEnclaveSignature impl Carrier.
func (c *empty) CascadeEnclaveSignature(req *task.CreateTaskRequest, args *carrier.CascadeEnclaveSignatureArgs) (
	signedEnclave string, err error) {
	return "", nil
}

// Cleanup impl Carrier.
func (c *empty) Cleanup() error {
	return nil
}
