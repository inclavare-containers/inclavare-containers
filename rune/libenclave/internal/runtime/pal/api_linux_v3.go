package enclave_runtime_pal // import "github.com/inclavare-containers/rune/libenclave/internal/runtime/pal"

/*
#include <stdlib.h>
#include <errno.h>

static int palGetLocalReport(void *sym, void *target_info, int target_info_len,
							void *report, int* report_len)
{
	return ((int (*)(void *, int, void*, int*))sym)(target_info, target_info_len,
								report, report_len);
}
*/
import "C"

import (
	"fmt"
	"github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/opencontainers/runc/libenclave/intelsgx"
	"unsafe"
)

type enclaveRuntimePalApiV3 struct {
}

func (pal *enclaveRuntimePalApiV3) getLocalReport(targetInfo []byte) ([]byte, error) {
	var ret C.int
	reportBufSize := int32(intelsgx.ReportLength)
	sym := nsenter.SymAddrPalGetLocalReport()

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
