package main

import (
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"unsafe"
)

func IsProductEnclave(reportBody intelsgx.ReportBody) (bool, error) {
	if unsafe.Sizeof(reportBody) != intelsgx.ReportBodyLength {
		return false, fmt.Errorf("len(report) is not %d, but %d", intelsgx.ReportBodyLength, unsafe.Sizeof(reportBody))
	}

	if reportBody.Attributes[0]&0x02 != 0x0 {
		return false, nil
	}

	return false, nil
}
