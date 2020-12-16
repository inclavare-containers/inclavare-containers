package enclave_runtime_pal // import "github.com/inclavare-containers/rune/libenclave/internal/runtime/pal"

/*
#include <stdlib.h>
#include "skeleton/liberpal-skeleton.h"

static int palGetVersion(void *sym)
{
	return ((int (*)(void)) sym) ();
}

static int palInitV1(void *sym, const char *args, const char *log_level)
{
	pal_attr_v1_t attr = {
		args,
		log_level,
	};

	return ((int (*)(pal_attr_v1_t *)) sym) (&attr);
}

static int palExecV1(void *sym, const char *exe, const char *argv[],
		     const char *envp[], int *exit_code, int stdin,
		     int stdout, int stderr)
{
	typedef struct {
		int stdin, stdout, stderr;
	} pal_stdio_fds;
	pal_stdio_fds fds = {
		stdin, stdout, stderr,
	};

	return ((int (*)(const char *, const char *[], pal_stdio_fds *, int *)) sym)
		(exe, argv, &fds, exit_code);
}

static int palDestroyV1(void *sym)
{
	return ((int (*)(void)) sym) ();
}
*/
import "C"

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
	"strings"
	"unsafe"
)

type enclaveRuntimePalApiV1 struct {
}

func (pal *enclaveRuntimePalApiV1) get_version() uint32 {
	logrus.Debugf("pal get_version() called")
	sym := symAddrPalVersion()
	if sym != nil {
		return uint32(C.palGetVersion(sym))
	}
	return 1
}

func (api *enclaveRuntimePalApiV1) init(args string, logLevel string) error {
	logrus.Debugf("pal init() called with args %s", args)

	a := C.CString(args)
	defer C.free(unsafe.Pointer(a))

	l := C.CString(logLevel)
	defer C.free(unsafe.Pointer(l))

	sym := symAddrPalInit()
	ret := C.palInitV1(sym, a, l)
	if ret < 0 {
		return fmt.Errorf("pal init() failed with %d", ret)
	}
	return nil
}

func (pal *enclaveRuntimePalApiV1) exec(cmd []string, envs []string, stdio [3]*os.File) (int32, error) {
	logrus.Debugf("pal exec() called with args %s", strings.Join(cmd, " "))

	// Skip cmd[0] as used as the executable.
	var exe *C.char
	argc := len(cmd) + 1
	pargs := make([]*C.char, argc)
	if argc > 1 {
		exe = C.CString(cmd[0])
		defer C.free(unsafe.Pointer(exe))

		for i, arg := range cmd {
			logrus.Debugf("arg[%d]: %s", i, arg)
			pargs[i] = C.CString(arg)
			defer C.free(unsafe.Pointer(pargs[i]))
		}
	}
	var argv **C.char = (**C.char)(unsafe.Pointer(&pargs[0]))

	envc := len(envs) + 1
	penvs := make([]*C.char, envc)
	if envc > 1 {
		for i, e := range envs {
			logrus.Debugf("env[%d]: %s", i, e)
			penvs[i] = C.CString(e)
			defer C.free(unsafe.Pointer(penvs[i]))
		}
	}
	var envp **C.char = (**C.char)(unsafe.Pointer(&penvs[0]))

	var exitCode int32
	stdin := C.int(int(stdio[0].Fd()))
	stdout := C.int(int(stdio[1].Fd()))
	stderr := C.int(int(stdio[2].Fd()))
	sym := symAddrPalExec()
	ret := C.palExecV1(sym, exe, argv, envp, (*C.int)(unsafe.Pointer(&exitCode)), stdin, stdout, stderr)
	if ret < 0 {
		return exitCode, fmt.Errorf("pal exec() failed with %d", ret)
	}
	return exitCode, nil
}

func (pal *enclaveRuntimePalApiV1) destroy() error {
	logrus.Debugf("pal destroy() called")

	sym := symAddrPalDestroy()
	ret := C.palDestroyV1(sym)
	if ret < 0 {
		return fmt.Errorf("pal destroy() failed with %d", ret)
	}
	return nil
}
