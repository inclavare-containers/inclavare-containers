package main

import (
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"io"
	"os"
	"strings"
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

func readFile(file string) ([]byte, error) {
	rf, err := os.Open(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file %s not found", file)
		}
		return nil, err
	}
	defer rf.Close()

	var rfi os.FileInfo
	rfi, err = rf.Stat()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, rfi.Size())
	if _, err = io.ReadFull(rf, buf); err != nil {
		return nil, fmt.Errorf("file %s read failed", file)
	}

	return buf, nil
}

func parseSgxEpidAttester(quoteType string, spid string) map[string]string {
	p := make(map[string]string)

	p["spid"] = spid
	p["linkable"] = "unlinkable"
	if strings.EqualFold(quoteType, intelsgx.QuoteTypeEpidLinkable) {
		p["linkable"] = "linkable"
	}

	return p
}
