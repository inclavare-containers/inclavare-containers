package enclave_runtime_pal // import "github.com/inclavare-containers/rune/libenclave/internal/runtime/pal"

import (
	"github.com/inclavare-containers/rune/libenclave/configs"
)

type enclaveRuntimePal struct {
	version        uint32
	enclavePoolID  string
	enclaveSubType string
}

func StartInitialization(config *configs.InitEnclaveConfig) (*enclaveRuntimePal, error) {
	pal := &enclaveRuntimePal{}
	return pal, nil
}
