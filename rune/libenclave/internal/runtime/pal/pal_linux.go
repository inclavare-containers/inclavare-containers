package enclave_runtime_pal // import "github.com/opencontainers/runc/libenclave/internal/runtime/pal"

import "C"

import (
	"encoding/binary"
	"fmt"
	"github.com/go-restruct/restruct"
	"github.com/opencontainers/runc/libenclave/attestation"
	"github.com/opencontainers/runc/libenclave/intelsgx"
	"log"
	"os"
)

const (
	palApiVersion = 2
)

func (pal *enclaveRuntimePal) Load(palPath string) (err error) {
	if err = pal.getPalApiVersion(); err != nil {
		return err
	}
	return nil
}

func (pal *enclaveRuntimePal) getPalApiVersion() error {
	api := &enclaveRuntimePalApiV1{}
	ver := api.get_version()
	if ver > palApiVersion {
		return fmt.Errorf("unsupported pal api version %d", ver)
	}
	pal.version = ver
	return nil
}

func (pal *enclaveRuntimePal) Init(args string, logLevel string) error {
	api := &enclaveRuntimePalApiV1{}
	return api.init(args, logLevel)
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
	return api.destroy()
}

func (pal *enclaveRuntimePal) GetSgxReport(targetInfo []byte, data []byte) ([]byte, error) {
	api := &enclaveRuntimePalApiV1{}
	return api.GetSgxReport(targetInfo, data)
}

func parseAttestParameters(Spid string, Product string, Subscription_key string) map[string]string {
	p := make(map[string]string)

	p["service-class"] = Product
	p["spid"] = Spid
	p["subscription-key"] = Subscription_key
	return p
}

func (pal *enclaveRuntimePal) Attest(Spid string, Quote_type string, Product string, Subscription_key string) (err error) {
	api := &enclaveRuntimePal{}
	if pal.GetSgxReport != nil {
		data := make([]byte, intelsgx.ReportLength)

		targetInfo, err := intelsgx.GetQeTargetInfo()
		if err != nil || len(targetInfo) != intelsgx.TargetinfoLength {
			if err == nil {
				return fmt.Errorf("len(targetInfo) is not %d, but %d", intelsgx.TargetinfoLength, len(targetInfo))
			}
			return err
		}

		// get local report of SGX
		report, err := api.GetSgxReport(targetInfo, data)
		if err != nil {
			return err
		}
		if len(report) != intelsgx.ReportLength {
			return fmt.Errorf("len(report) is not %d, but %d", intelsgx.ReportLength, len(report))
		}

		// get quote from QE(aesmd)
		var quote_type bool = false
		if Quote_type == "SGX_LINKABLE_SIGNATURE" {
			quote_type = true
		}
		quote, err := intelsgx.GetQuote(report, Spid, quote_type)
		if err != nil {
			return err
		}

		q := &intelsgx.Quote{}
		if err := restruct.Unpack(quote, binary.LittleEndian, &q); err != nil {
			return err
		}

		// get IAS remote attestation report
		var verbose bool = true
		p := parseAttestParameters(Spid, Product, Subscription_key)
		svc, err := attestation.NewService(p, verbose)
		if err != nil {
			log.Fatal(err)
			return err
		}

		if err = svc.Check(quote); err != nil {
			log.Fatal(err)
			return err
		}

		status := svc.Verify(quote)
		if status.ErrorMessage != "" {
			return fmt.Errorf("%s", status.ErrorMessage)
		}
		svc.ShowStatus(status)
		return nil
	}

	return nil
}
