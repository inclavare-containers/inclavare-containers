package enclave_runtime_pal // import "github.com/opencontainers/runc/libenclave/internal/runtime/pal"

// #cgo LDFLAGS: -ldl
// #define _GNU_SOURCE
// #include <stdlib.h>
// #include <dlfcn.h>
import "C"

import (
	"fmt"
	"os"
	"path"
	"strings"
	"unsafe"
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
	pal.name = palName

	if err = pal.getPalApiVersion(); err != nil {
		return err
	}
	return pal.probeApi()
}

func (pal *enclaveRuntimePal) getPalApiVersion() error {
	return pal.getSymbol("version",
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
	err = pal.getSymbol("init",
		func(sym unsafe.Pointer) error {
			if sym == nil {
				return fmt.Errorf("unresolved api interface %s_pal_init", pal.name)
			}
			pal.init = sym
			return nil
		},
	)
	if err != nil {
		return err
	}

	err = pal.getSymbol("exec",
		func(sym unsafe.Pointer) error {
			if sym == nil {
				return fmt.Errorf("unresolved api interface %s_pal_exec", pal.name)
			}
			pal.exec = sym
			return nil
		},
	)
	if err != nil {
		return err
	}

	err = pal.getSymbol("kill",
		func(sym unsafe.Pointer) error {
			if sym == nil {
				if pal.version == 1 {
					return nil
				}
				return fmt.Errorf("unresolved api interface %s_pal_kill", pal.name)
			}
			pal.kill = sym
			return nil
		},
	)
	if err != nil {
		return err
	}

	err = pal.getSymbol("destroy",
		func(sym unsafe.Pointer) error {
			if sym == nil {
				return fmt.Errorf("unresolved api interface %s_pal_destroy", pal.name)
			}
			pal.destroy = sym
			return nil
		},
	)
	return err
}

func (pal *enclaveRuntimePal) getSymbol(apiName string, handler func(sym unsafe.Pointer) error) error {
	symName := fmt.Sprintf("%s_pal_%s", pal.name, apiName)
	sn := C.CString(symName)
	defer C.free(unsafe.Pointer(sn))

	sym := C.dlsym(pal.handle, sn)
	return handler(sym)
}

func (pal *enclaveRuntimePal) Name() string {
	return fmt.Sprintf("%s (API version %d)", pal.name, pal.version)
}

func (pal *enclaveRuntimePal) Init(args string, logLevel string) error {
	api := &enclaveRuntimePalApiV1{}
	return api.init(pal.init, args, "off")
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
