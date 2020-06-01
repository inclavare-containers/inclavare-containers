package enclave_runtime_pal // import "github.com/opencontainers/runc/libenclave/internal/runtime/pal"

import (
	"fmt"
	"os"
	"path"
	"strings"
)

const (
	palPrefix = "liberpal-"
	palSuffix = ".so"
)

func (pal *enclaveRuntimePal) Load(palPath string) (err error) {
	bp := path.Base(palPath)
	if !strings.HasPrefix(bp, palPrefix) {
		return fmt.Errorf("not found pal prefix pattern in pal %s\n", palPath)
	}
	if !strings.HasSuffix(bp, palSuffix) {
		return fmt.Errorf("not found pal suffix pattern in pal %s\n", palPath)
	}
	palName := strings.TrimSuffix(strings.TrimPrefix(bp, palPrefix), palSuffix)

	pal.name = palName

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

func (pal *enclaveRuntimePal) Name() string {
	return fmt.Sprintf("%s (API version %d)", pal.name, pal.version)
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
