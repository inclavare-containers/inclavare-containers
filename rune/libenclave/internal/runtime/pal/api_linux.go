package enclave_runtime_pal // import "github.com/opencontainers/runc/libenclave/internal/runtime/pal"

/*
#include <stdlib.h>

static int palInitV1(void *sym, const char *args, const char *log_level)
{
	typedef struct {
		const char*     instance_dir;
		const char*     log_level;
	} pal_attr_t;
	pal_attr_t attr = {
		args,
		log_level,
	};

	return ((int (*)(pal_attr_t *))sym)(&attr);
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

	return ((int (*)(const char *, const char *[], pal_stdio_fds *, int *))sym)
		(exe, argv, &fds, exit_code);
}

static int palKillV1(void *sym, int sig, int pid)
{
	return ((int (*)(int, int))sym)(sig, pid);
}

static int palDestroyV1(void *sym)
{
	return ((int (*)(void))sym)();
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

const (
	palApiVersion = 1
)

type enclaveRuntimePalApiV1 struct {
}

func (api *enclaveRuntimePalApiV1) init(sym unsafe.Pointer, args string, logLevel string) error {
	logrus.Debugf("pal init() called with args %s", args)

	a := C.CString(args)
	defer C.free(unsafe.Pointer(a))

	l := C.CString(logLevel)
	defer C.free(unsafe.Pointer(l))

	ret := C.palInitV1(sym, a, l)
	if ret < 0 {
		return fmt.Errorf("pal init() failed with %d", ret)
	}
	return nil
}

func (pal *enclaveRuntimePalApiV1) exec(sym unsafe.Pointer, cmd []string, envs []string, stdio [3]*os.File) (int32, error) {
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
	ret := C.palExecV1(sym, exe, argv, envp, (*C.int)(unsafe.Pointer(&exitCode)), stdin, stdout, stderr)
	if ret < 0 {
		return exitCode, fmt.Errorf("pal exec() failed with %d", ret)
	}
	return exitCode, nil
}

func (pal *enclaveRuntimePalApiV1) kill(sym unsafe.Pointer, sig int, pid int) error {
	sigNum := C.int(sig)
	pidNum := C.int(pid)
	ret := C.palKillV1(sym, sigNum, pidNum)
	if ret < 0 {
		return fmt.Errorf("pal kill() failed with %d", ret)
	}
	return nil
}

func (pal *enclaveRuntimePalApiV1) destroy(sym unsafe.Pointer) error {
	logrus.Debugf("pal destroy() called")

	ret := C.palDestroyV1(sym)
	if ret < 0 {
		return fmt.Errorf("pal destroy() failed with %d", ret)
	}
	return nil
}
