package enclave_runtime_pal // import "github.com/inclavare-containers/rune/libenclave/internal/runtime/pal"

/*
#include <stdlib.h>

static int palCreateProcessV2(void *sym, const char *exe, const char *argv[],
			      const char *envp[], int stdin, int stdout,
			      int stderr, int *pid)
{
	typedef struct {
		int stdin, stdout, stderr;
	} pal_stdio_fds;

	typedef struct {
		const char *path;
		const char **argv;
		const char **env;
		pal_stdio_fds *fds;
		int *pid;
	} pal_create_process_args;

	pal_stdio_fds fds = {
		stdin, stdout, stderr,
	};

	pal_create_process_args create_process_args = {
		exe,
		argv,
		envp,
		&fds,
		pid,
	};

	return ((int (*)(pal_create_process_args *)) sym)
		(&create_process_args);
}

static int palExecV2(void *sym, int pid, int *exit_code)
{
	typedef struct {
		int pid;
		int *exit_value;
	} pal_exec_args;

	pal_exec_args args = {
		pid,
		exit_code,
	};

	return ((int (*)(pal_exec_args *)) sym)
		(&args);
}

static int palKillV2(void *sym, int pid, int sig)
{
	return ((int (*)(int, int)) sym) (pid, sig);
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

type enclaveRuntimePalApiV2 struct {
}

func (pal *enclaveRuntimePalApiV2) exec(cmd []string, envs []string, stdio [3]*os.File) (int32, error) {
	logrus.Debugf("pal exec() called with args %s", strings.Join(cmd, " "))

	// Skip cmd[0] as used as the executable.
	var exe *C.char
	argc := len(cmd) + 1
	pargs := make([]*C.char, argc)
	exe = C.CString(cmd[0])
	defer C.free(unsafe.Pointer(exe))
	if argc > 1 {
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
	var pid int32
	stdin := C.int(int(stdio[0].Fd()))
	stdout := C.int(int(stdio[1].Fd()))
	stderr := C.int(int(stdio[2].Fd()))
	sym := symAddrPalCreateProcess()

	ret := C.palCreateProcessV2(sym, exe, argv, envp, stdin, stdout, stderr, (*C.int)(unsafe.Pointer(&pid)))
	if ret < 0 {
		return exitCode, fmt.Errorf("pal create process() failed with %d", ret)
	}

	sym = symAddrPalExec()
	ret = C.palExecV2(sym, C.int(pid), (*C.int)(unsafe.Pointer(&exitCode)))
	if ret < 0 {
		return exitCode, fmt.Errorf("pal exec() failed with %d", ret)
	}
	return exitCode, nil
}

func (pal *enclaveRuntimePalApiV2) kill(pid int, sig int) error {
	pidNum := C.int(pid)
	sigNum := C.int(sig)
	sym := symAddrPalKill()
	if sym == nil {
		return fmt.Errorf("pal kill() not implemented")
	}

	ret := C.palKillV2(sym, pidNum, sigNum)
	if ret < 0 {
		return fmt.Errorf("pal kill() failed with %d", ret)
	}
	return nil
}
