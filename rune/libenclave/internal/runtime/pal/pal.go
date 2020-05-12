package enclave_runtime_pal // import "github.com/opencontainers/runc/libenclave/internal/runtime/pal"

import (
	"github.com/opencontainers/runc/libenclave/configs"
	"unsafe"
)

type enclaveRuntimePal struct {
	handle  unsafe.Pointer
	name    string
	version uint32
	init    unsafe.Pointer
	exec    unsafe.Pointer
	kill    unsafe.Pointer
	destroy unsafe.Pointer
}

func StartInitialization(config *configs.InitEnclaveConfig) (*enclaveRuntimePal, error) {
	pal := &enclaveRuntimePal{}
	return pal, nil
}
