package enclave_runtime_pal // import "github.com/inclavare-containers/rune/libenclave/internal/runtime/pal"

import (
	"encoding/binary"
	"fmt"
	"github.com/go-restruct/restruct"
	"github.com/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/inclavare-containers/rune/libenclave/attestation"
	"github.com/inclavare-containers/rune/libenclave/epm"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"log"
	"os"
	"strings"
)

const (
	palApiVersion         = 3
	InvalidEpmID   string = "InvalidEPMID"
	EnclaveSubType string = "skeleton-0.0.0"
)

func (pal *enclaveRuntimePal) Init(args string, logLevel string) error {
	var enclaveinfo *v1alpha1.Enclave
	/* Assuming v1 is used */
	api := &enclaveRuntimePalApiV1{}
	ver := api.get_version()
	if ver > palApiVersion {
		return fmt.Errorf("unsupported pal api version %d", ver)
	}

	pal.version = ver
	pal.enclavePoolID = InvalidEpmID

	if ver < 3 {
		return api.init(args, logLevel)
	}

	var addr uint64 = 0
	var fd int = -1

	apiV3 := &enclaveRuntimePalApiV3{}

	no_epm := true
	if !strings.Contains(args, "no-epm") {
		no_epm = false
		/* enclaveinfo.Layout retrieves from /proc/pid/mmaps, in file
		 * mmaps sgx device mmaping address is sorted from low
		 * address to high one. So layout[0].Addr will be minimum.
		 */
		pal.enclaveSubType = EnclaveSubType
		enclaveinfo = epm.GetEnclave(pal.enclaveSubType)
		if enclaveinfo != nil {
			epm.SgxMmap(*enclaveinfo)
			addr = enclaveinfo.Layout[0].Addr
			fd = int(enclaveinfo.Fd)
		}
	}
	err := apiV3.init(args, logLevel, fd, addr)
	if err == nil && !no_epm {
		pal.enclavePoolID = epm.SavePreCache(pal.enclaveSubType, enclaveinfo)
	}

	return err
}

func (pal *enclaveRuntimePal) Exec(cmd []string, envp []string, stdio [3]*os.File) (int32, error) {
	if pal.version == 1 {
		api := &enclaveRuntimePalApiV1{}
		return api.exec(cmd, envp, stdio)
	}

	api := &enclaveRuntimePalApiV2{}
	return api.exec(cmd, envp, stdio)
}

func (pal *enclaveRuntimePal) Kill(pid int, sig int) error {
	if pal.version == 1 {
		return nil
	}

	api := &enclaveRuntimePalApiV2{}
	return api.kill(pid, sig)
}

func (pal *enclaveRuntimePal) Destroy() error {
	api := &enclaveRuntimePalApiV1{}

	if pal.enclavePoolID != InvalidEpmID {
		epm.SaveEnclave(pal.enclavePoolID, pal.enclaveSubType)
	}
	return api.destroy()
}

func (pal *enclaveRuntimePal) GetLocalReport(targetInfo []byte) ([]byte, error) {
	if pal.version >= 3 {
		api := &enclaveRuntimePalApiV3{}
		return api.getLocalReport(targetInfo)
	}

	return nil, fmt.Errorf("unsupported pal api version %d", pal.version)
}

func parseAttestParameters(spid string, subscriptionKey string, product bool) map[string]string {
	p := make(map[string]string)

	p["spid"] = spid
	p["subscription-key"] = subscriptionKey
	p["service-class"] = "dev"
	if product {
		p["service-class"] = "product"
	}

	return p
}

func (pal *enclaveRuntimePal) Attest(isRA bool, quoteType string, spid string, subscriptionKey string) ([]byte, error) {
	if pal.GetLocalReport == nil {
		return nil, nil
	}

	targetInfo, err := intelsgx.GetQeTargetInfo()
	if err != nil {
		return nil, err
	}

	if len(targetInfo) != intelsgx.TargetinfoLength {
		return nil, fmt.Errorf("len(targetInfo) is not %d, but %d", intelsgx.TargetinfoLength, len(targetInfo))
	}

	// get local report of SGX
	report, err := pal.GetLocalReport(targetInfo)
	if err != nil {
		return nil, err
	}
	if len(report) != intelsgx.ReportLength {
		return nil, fmt.Errorf("len(report) is not %d, but %d", intelsgx.ReportLength, len(report))
	}

	// return local report if the value of iaRA equals to false.
	if isRA == false {
		return report, nil
	}

	// get quote from QE(aesmd)
	quote, err := intelsgx.GetQuoteEx(quoteType, report, spid)
	if err != nil {
		return nil, err
	}

	q := &intelsgx.Quote{}
	if err := restruct.Unpack(quote, binary.LittleEndian, &q); err != nil {
		return nil, err
	}

	product, err := intelsgx.IsProductEnclave(q.ReportBody)
	if err != nil {
		return nil, err
	}

	// get IAS remote attestation report
	p := parseAttestParameters(spid, subscriptionKey, product)
	challenger, err := attestation.NewChallenger("sgx-epid", p)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	if err = challenger.Check(quote); err != nil {
		log.Fatal(err)
		return nil, err
	}

	statusCode, specificStatus, _, err := challenger.GetReport(quote, 0)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	challenger.ShowReportStatus(statusCode, specificStatus)

	return report, nil
}
