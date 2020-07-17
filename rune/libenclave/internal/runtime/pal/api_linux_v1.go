package enclave_runtime_pal // import "github.com/opencontainers/runc/libenclave/internal/runtime/pal"

/*
#include <stdlib.h>
#include <errno.h>

static int palGetVersion(void *sym)
{
	return ((int (*)(void))sym)();
}

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

static int pal_get_reportV1(void *sym, void *target_info, int target_info_len,
			void *data, int data_len, void *report, int* report_len)
{
	return ((int (*)(void *, int, void*, int, void*, int*))sym)(target_info, target_info_len,
								data, data_len, report, report_len);
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

static int palDestroyV1(void *sym)
{
	return ((int (*)(void))sym)();
}
*/
import "C"

import (
	"fmt"
	"github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/opencontainers/runc/libenclave/intelsgx"
	"github.com/sirupsen/logrus"
	"os"
	"strings"
	"unsafe"
)

type enclaveRuntimePalApiV1 struct {
}

func (pal *enclaveRuntimePalApiV1) get_version() uint32 {
	logrus.Debugf("pal get_version() called")
	sym := nsenter.SymAddrPalVersion()
	if sym != nil {
		return uint32(C.palGetVersion(sym))
	} else {
		return 1
	}
}

func (api *enclaveRuntimePalApiV1) init(args string, logLevel string) error {
	logrus.Debugf("pal init() called with args %s", args)

	a := C.CString(args)
	defer C.free(unsafe.Pointer(a))

	l := C.CString(logLevel)
	defer C.free(unsafe.Pointer(l))

	sym := nsenter.SymAddrPalInit()
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
	sym := nsenter.SymAddrPalExec()
	ret := C.palExecV1(sym, exe, argv, envp, (*C.int)(unsafe.Pointer(&exitCode)), stdin, stdout, stderr)
	if ret < 0 {
		return exitCode, fmt.Errorf("pal exec() failed with %d", ret)
	}
	return exitCode, nil
}

func (pal *enclaveRuntimePalApiV1) destroy() error {
	logrus.Debugf("pal destroy() called")

	sym := nsenter.SymAddrPalDestroy()
	ret := C.palDestroyV1(sym)
	if ret < 0 {
		return fmt.Errorf("pal destroy() failed with %d", ret)
	}
	return nil
}

func (pal *enclaveRuntimePalApiV1) GetSgxReport(targetInfo []byte, data []byte) ([]byte, error) {
	var ret C.int
	reportBufSize := int32(intelsgx.ReportLength)
	sym := nsenter.SymAddrPalGetSgxReport()

	for {
		report := make([]byte, reportBufSize)
		var pTargetInfo unsafe.Pointer = nil
		var pData unsafe.Pointer = nil
		if len(targetInfo) > 0 {
			pTargetInfo = unsafe.Pointer(&targetInfo[0])
		}
		if len(data) > 0 {
			pData = unsafe.Pointer(&data[0])
		}
		ret = C.pal_get_reportV1(sym, pTargetInfo,
			C.int(len(targetInfo)),
			pData,
			C.int(len(data)),
			unsafe.Pointer(&report[0]),
			(*C.int)(unsafe.Pointer(&reportBufSize)))

		if ret == 0 {
			return report, nil
		}

		if ret != -C.EAGAIN {
			break
		}
	}

	return nil, fmt.Errorf("C.do_pal_get_report() failed, return %d.\n", ret)
}
