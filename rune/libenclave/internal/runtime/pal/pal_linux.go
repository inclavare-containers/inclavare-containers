package enclave_runtime_pal // import "github.com/inclavare-containers/rune/libenclave/internal/runtime/pal"

import (
	"encoding/binary"
	"fmt"
	"github.com/go-restruct/restruct"
	"github.com/inclavare-containers/rune/libenclave/attestation"
	_ "github.com/inclavare-containers/rune/libenclave/attestation/sgx/ias"
	"github.com/inclavare-containers/rune/libenclave/epm"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"log"
	"os"
	"strings"
)

const (
	palApiVersion        = 3
	InvalidEpmID  string = "InvalidEPMID"
)

func (pal *enclaveRuntimePal) Init(args string, logLevel string) error {
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

	/* FIXME: If EPM provides epm existence detect API, the static
	 * check will be substituted. Enclave pool will be distinguished
	 * by pal.Type and Pal.subType once subType can be provided by new
	 * PAL interface in future.
	 */
	var addr uint64 = 0
	var fd int = -1

	apiV3 := &enclaveRuntimePalApiV3{}

	if strings.Contains(args, "epm") {
		/* enclaveinfo.Layout retrieves from /proc/pid/mmaps, in file
		 * mmaps /dev/sgx/enclave mmaping address is sorted from low
		 * address to high one. So layout[0].Addr will be minimum.
		 */
		enclaveinfo := epm.GetEnclave()
		if enclaveinfo != nil {
			epm.SgxMmap(*enclaveinfo)
			addr = enclaveinfo.Layout[0].Addr
			fd = int(enclaveinfo.Fd)
		}
	}

	err := apiV3.init(args, logLevel, fd, addr)
	if err == nil && strings.Contains(args, "epm") {
		pal.enclavePoolID = epm.SavePreCache()
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
		epm.SaveEnclave(pal.enclavePoolID)
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

func (pal *enclaveRuntimePal) Attest(isDCAP bool, isRA bool, spid string, subscriptionKey string, quoteType uint32) ([]byte, error) {
	if pal.GetLocalReport == nil {
		return nil, nil
	}

	var targetInfo []byte
	var err error

	if isDCAP {
		targetInfo, err = intelsgx.GetDCAPTargetInfo()
		if err != nil {
			return nil, err
		}
	} else {
		targetInfo, err = intelsgx.GetQeTargetInfo()
		if err != nil {
			return nil, err
		}
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

	if isDCAP {
		return nil, fmt.Errorf("unsupported to get DCAP remote attestion!")
	}

	// get quote from QE(aesmd)
	linkable := false
	if quoteType == intelsgx.QuoteSignatureTypeLinkable {
		linkable = true
	}
	quote, err := intelsgx.GetQuote(report, spid, linkable)
	if err != nil {
		return nil, err
	}

	q := &intelsgx.Quote{}
	if err = restruct.Unpack(quote, binary.LittleEndian, &q); err != nil {
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

	status, _, err := challenger.GetReport(quote, 0)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	challenger.ShowReportStatus(status)

	return report, nil
}
