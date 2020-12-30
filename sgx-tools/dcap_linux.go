package main // import "github.com/inclavare-containers/sgx-tools"

/*
#cgo LDFLAGS:-lsgx_dcap_ql

#include <stdio.h>
#include <stdlib.h>
#include "sgx_urts.h"
#include "sgx_report.h"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_pce.h"
#include "sgx_error.h"
#include "sgx_quote_3.h"

static int getDCAPTargetInfo(void *target_info, int target_info_len)
{
	if (!target_info) {
		printf("Error: the input parameter target_info is NULL\n");
		return -1;
	}
	if (target_info_len != sizeof(sgx_target_info_t)) {
		printf("Error: the target_info_len is not %d, but %d\n", sizeof(sgx_target_info_t), target_info_len);
		return -1;
	}

	quote3_error_t qe3_ret = SGX_QL_SUCCESS;
	qe3_ret = sgx_qe_get_target_info(target_info);
	if (SGX_QL_SUCCESS != qe3_ret) {
        	printf("Error in sgx_qe_get_target_info. 0x%04x\n", qe3_ret);
		return -1;
	}

	return qe3_ret;
}
*/
import "C"

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/go-restruct/restruct"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"github.com/sirupsen/logrus"
	"unsafe"
)

func GetDCAPTargetInfo() ([]byte, error) {
	fmt.Printf("Get DCAP target info!\n")
	ti := make([]byte, intelsgx.TargetinfoLength)

	ret := C.getDCAPTargetInfo(unsafe.Pointer(&ti[0]),
		C.int(len(ti)))

	if ret != 0 {
		return nil, fmt.Errorf("C.getDCAPTargetInfo() failed, return %d.\n", ret)
	}

	targetInfo := &intelsgx.Targetinfo{}
	if err := restruct.Unpack(ti, binary.LittleEndian, &targetInfo); err != nil {
		return nil, err
	}

	logrus.Infof("Quoting Enclave's TARGETINFO:\n")
	logrus.Infof("  Enclave Hash:       0x%v\n",
		hex.EncodeToString(targetInfo.Measurement[:]))
	logrus.Infof("  Enclave Attributes: 0x%v\n",
		hex.EncodeToString(targetInfo.Attributes[:]))
	logrus.Infof("  CET Attributes:     %#02x\n",
		targetInfo.CetAttributes)
	logrus.Infof("  Config SVN:         %#04x\n",
		targetInfo.ConfigSvn)
	logrus.Infof("  Misc Select:        %#08x\n",
		targetInfo.MiscSelect)
	logrus.Infof("  Config ID:          0x%v\n",
		hex.EncodeToString(targetInfo.ConfigId[:]))

	return ti, nil
}

func GetDCAPQuoteSize() {
}

func GetDCAPQuote() {
}
