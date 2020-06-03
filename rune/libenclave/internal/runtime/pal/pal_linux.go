package enclave_runtime_pal // import "github.com/opencontainers/runc/libenclave/internal/runtime/pal"

import (
	"fmt"
	"os"
)

func (pal *enclaveRuntimePal) Load(palPath string) (err error) {
	if err = pal.getPalApiVersion(); err != nil {
		return err
	}
	return nil
}

func (pal *enclaveRuntimePal) getPalApiVersion() error {
	api := &enclaveRuntimePalApiV1{}
	ver := api.get_version()
	if ver > palApiVersion {
		return fmt.Errorf("unsupported pal api version %d", ver)
	}
	pal.version = ver
	return nil
}

func (pal *enclaveRuntimePal) Init(args string, logLevel string) error {
	api := &enclaveRuntimePalApiV1{}
	return api.init(args, logLevel)
}

func (pal *enclaveRuntimePal) Attest() (err error) {
	return nil
}

func (pal *enclaveRuntimePal) Exec(cmd []string, envp []string, stdio [3]*os.File) (int32, error) {
	api := &enclaveRuntimePalApiV1{}
	return api.exec(cmd, envp, stdio)
}

func (pal *enclaveRuntimePal) Kill(sig int, pid int) error {
	if pal.version >= 2 {
		api := &enclaveRuntimePalApiV1{}
		return api.kill(sig, pid)
	}
	return nil
}

func (pal *enclaveRuntimePal) Destroy() error {
	api := &enclaveRuntimePalApiV1{}
	return api.destroy()
}
