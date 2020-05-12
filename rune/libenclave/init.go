package libenclave // import "github.com/opencontainers/runc/libenclave"

import (
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libenclave/intelsgx"
)

var (
	enclaveHwType string = ""
)

func IsEnclaveEnabled(e *configs.Enclave) bool {
	if e == nil {
		return false
	}

	if !IsEnclaveHwEnabled(e.Type) {
		return false
	}

	return true
}

// Check whether enclave-based hardware is supported or not
func IsEnclaveHwEnabled(etype string) bool {
	if etype == "" && enclaveHwType != "" {
		return true
	}

	return etype == enclaveHwType
}

func init() {
	if intelsgx.IsSgxSupported() {
		enclaveHwType = configs.EnclaveHwIntelSgx
	}
}
