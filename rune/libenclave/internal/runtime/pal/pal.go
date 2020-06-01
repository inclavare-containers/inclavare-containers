package enclave_runtime_pal // import "github.com/opencontainers/runc/libenclave/internal/runtime/pal"

import (
	"github.com/opencontainers/runc/libenclave/configs"
)

type enclaveRuntimePal struct {
	name    string
	version uint32
}

func StartInitialization(config *configs.InitEnclaveConfig) (*enclaveRuntimePal, error) {
	pal := &enclaveRuntimePal{}
	return pal, nil
}
