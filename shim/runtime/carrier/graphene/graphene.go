package graphene

import (
	"errors"

	"github.com/containerd/containerd/runtime/v2/task"

	"github.com/inclavare-containers/shim/runtime/carrier"
)

var _ carrier.Carrier = &graphene{}

type graphene struct {
	//TODO
}

func NewGrapheneCarrier() (carrier.Carrier, error) {
	//TODO
	return nil, errors.New("Carrier graphene has not been implemented")
}

// Name impl Carrier.
func (c *graphene) Name() string {
	return "graphene"
}

// BuildUnsignedEnclave impl Carrier.
func (c *graphene) BuildUnsignedEnclave(req *task.CreateTaskRequest, args *carrier.BuildUnsignedEnclaveArgs) (
	unsignedEnclave string, err error) {
	//TODO
	return "", errors.New("graphene BuildUnsignedEnclave unimplemented")
}

// GenerateSigningMaterial impl Carrier.
func (c *graphene) GenerateSigningMaterial(req *task.CreateTaskRequest, args *carrier.CommonArgs) (
	signingMaterial string, err error) {
	//TODO
	return "", errors.New("graphene GenerateSigningMaterial unimplemented")
}

// SignMaterial impl Carrier.
func (c *graphene) SignMaterial(req *task.CreateTaskRequest, signingMaterial, serverAddress string) (publicKey, signature string, err error) {
	//TODO
	return "", "", nil
}

// CascadeEnclaveSignature impl Carrier.
func (c *graphene) CascadeEnclaveSignature(req *task.CreateTaskRequest, args *carrier.CascadeEnclaveSignatureArgs) (
	signedEnclave string, err error) {
	//TODO
	return "", errors.New("graphene CascadeEnclaveSignature unimplemented")
}

// Cleanup impl Carrier.
func (c *graphene) Cleanup(err error) error {
	//TODO
	return errors.New("graphene Cleanup unimplemented")
}
