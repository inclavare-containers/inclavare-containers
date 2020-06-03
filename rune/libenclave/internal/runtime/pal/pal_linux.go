package enclave_runtime_pal // import "github.com/opencontainers/runc/libenclave/internal/runtime/pal"

// #cgo LDFLAGS: -ldl
// #define _GNU_SOURCE
// #include <stdlib.h>
// #include <dlfcn.h>
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

func (pal *enclaveRuntimePal) Load(palPath string) (err error) {
	p := C.CString(palPath)
	defer C.free(unsafe.Pointer(p))
	handle := C.dlmopen(C.LM_ID_NEWLM, p, C.RTLD_LAZY)
	if handle == nil {
		return fmt.Errorf("unable to load pal %s\n", palPath)
	}
	defer func() {
		if err != nil {
			C.dlclose(handle)
		}
	}()

	pal.handle = handle

	if err = pal.getPalApiVersion(); err != nil {
		return err
	}
	return pal.probeApi()
}

func (pal *enclaveRuntimePal) getPalApiVersion() error {
	return pal.getSymbol("pal_version",
		func(sym unsafe.Pointer) error {
			if sym == nil {
				pal.version = 1
			} else {
				ver := *(*uint32)(sym)
				if ver > palApiVersion {
					return fmt.Errorf("unsupported pal api version %d", ver)
				}
				pal.version = ver
			}
			return nil
		},
	)
}

func (pal *enclaveRuntimePal) probeApi() (err error) {
	err = pal.getSymbol("pal_init",
		func(sym unsafe.Pointer) error {
			if sym == nil {
				return fmt.Errorf("unresolved api interface pal_init")
			}
			pal.init = sym
			return nil
		},
	)
	if err != nil {
		return err
	}

	err = pal.getSymbol("pal_exec",
		func(sym unsafe.Pointer) error {
			if sym == nil {
				return fmt.Errorf("unresolved api interface pal_exec")
			}
			pal.exec = sym
			return nil
		},
	)
	if err != nil {
		return err
	}

	err = pal.getSymbol("pal_kill",
		func(sym unsafe.Pointer) error {
			if sym == nil {
				if pal.version == 1 {
					return nil
				}
				return fmt.Errorf("unresolved api interface pal_kill")
			}
			pal.kill = sym
			return nil
		},
	)
	if err != nil {
		return err
	}

	err = pal.getSymbol("pal_destroy",
		func(sym unsafe.Pointer) error {
			if sym == nil {
				return fmt.Errorf("unresolved api interface pal_destroy")
			}
			pal.destroy = sym
			return nil
		},
	)
	return err
}

func (pal *enclaveRuntimePal) getSymbol(apiName string, handler func(sym unsafe.Pointer) error) error {
	an := C.CString(apiName)
	defer C.free(unsafe.Pointer(an))

	sym := C.dlsym(pal.handle, an)
	return handler(sym)
}

func (pal *enclaveRuntimePal) Init(args string, logLevel string) error {
	api := &enclaveRuntimePalApiV1{}
	return api.init(pal.init, args, logLevel)
}

func (pal *enclaveRuntimePal) Attest() (err error) {
	return nil
}

func (pal *enclaveRuntimePal) Exec(cmd []string, envp []string, stdio [3]*os.File) (int32, error) {
	api := &enclaveRuntimePalApiV1{}
	return api.exec(pal.exec, cmd, envp, stdio)
}

func (pal *enclaveRuntimePal) Kill(sig int, pid int) error {
	if pal.version >= 2 {
		api := &enclaveRuntimePalApiV1{}
		return api.kill(pal.kill, sig, pid)
	}
	return nil
}

func (pal *enclaveRuntimePal) Destroy() error {
	api := &enclaveRuntimePalApiV1{}
	return api.destroy(pal.destroy)
}
