package enclave_runtime_pal // import "github.com/inclavare-containers/rune/libenclave/internal/runtime/pal"

/*
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include "skeleton/liberpal-skeleton.h"

static int palInitV3(void *sym, const char *args, const char *log_level, int fd,
		     uint64_t addr)
{
	pal_attr_v3_t attr_v3 = {
		args,
		log_level,
		fd,
		addr,
	};

	return ((int (*)(pal_attr_v3_t *)) sym) (&attr_v3);
}

static int palGetLocalReport(void *sym, void *target_info, int target_info_len,
			     void *report, int *report_len)
{
	return ((int (*)(void *, int, void *, int *)) sym) (target_info,
							    target_info_len,
							    report, report_len);
}
*/
import "C"

import (
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"github.com/sirupsen/logrus"
	"unsafe"
)

type enclaveRuntimePalApiV3 struct {
}

func (api *enclaveRuntimePalApiV3) init(args string, logLevel string, fd int, addr uint64) error {
	logrus.Debugf("pal init() called with args %s", args)

	a := C.CString(args)
	defer C.free(unsafe.Pointer(a))

	l := C.CString(logLevel)
	defer C.free(unsafe.Pointer(l))

	f := C.int(fd)
	r := C.ulong(addr)

	sym := symAddrPalInit()
	ret := C.palInitV3(sym, a, l, f, r)
	if ret < 0 {
		return fmt.Errorf("pal init() failed with %d", ret)
	}
	return nil
}

func (pal *enclaveRuntimePalApiV3) getLocalReport(targetInfo []byte) ([]byte, error) {
	var ret C.int
	reportBufSize := int32(intelsgx.ReportLength)
	sym := symAddrPalGetLocalReport()

	report := make([]byte, reportBufSize)
	var pTargetInfo unsafe.Pointer = nil
	if len(targetInfo) > 0 {
		pTargetInfo = unsafe.Pointer(&targetInfo[0])
	}

	ret = C.palGetLocalReport(sym, pTargetInfo,
		C.int(len(targetInfo)),
		unsafe.Pointer(&report[0]),
		(*C.int)(unsafe.Pointer(&reportBufSize)))
	if ret == 0 {
		return report, nil
	}

	return nil, fmt.Errorf("C.palGetLocalReport() failed, return %d.\n", ret)
}
