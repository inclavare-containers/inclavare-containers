package sgx_challenger // import "github.com/inclavare-containers/rune/libenclave/attestation/internal/sgx/challenger"

import (
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/attestation/internal/registration"
	"github.com/inclavare-containers/rune/libenclave/attestation/internal/sgx/ias"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"github.com/sirupsen/logrus"
)

type sgxEpidChallenger struct {
	ias *ias.IasAttestation
}

/* The definition of StatusCode */
const (
	StatusSgxBit = 0x80000000
)

func (epid *sgxEpidChallenger) Name() string {
	return intelsgx.AttestationEpid
}

func (epid *sgxEpidChallenger) New(cfg map[string]string) error {
	ias, err := ias.NewIasAttestation(cfg)
	if err != nil {
		return err
	}
	epid.ias = ias

	return nil
}

func (epid *sgxEpidChallenger) Check(quote []byte) error {
	return epid.ias.CheckQuote(quote)
}

func (epid *sgxEpidChallenger) Verify(quote []byte) (uint32, interface{}, error) {
	s, err := epid.ias.VerifyQuote(quote)

	return StatusSgxBit, s, err
}

func (epid *sgxEpidChallenger) GetReport(quote []byte, nonce uint64) (uint32, interface{}, map[string]string, error) {
	s, report, err := epid.ias.RetrieveIasReport(quote, nonce)

	return StatusSgxBit, s, report, err
}

func (epid *sgxEpidChallenger) ShowReportStatus(statusCode uint32, specificStatus interface{}) error {
	if statusCode&StatusSgxBit != StatusSgxBit {
		return fmt.Errorf("Report status is used for SGX EPID-based")
	}

	s, ok := specificStatus.(*ias.IasReportStatus)
	if ok {
		logrus.Infof("Request ID: %s\n", s.RequestId)
		logrus.Infof("Report ID: %s\n", s.ReportId)
		logrus.Infof("Timestamp: %s\n", s.Timestamp)
		logrus.Infof("IsvEnclaveQuoteStatus: %s\n", s.QuoteStatus)
	}

	return nil
}

func init() {
	if err := registration.RegisterChallenger(&sgxEpidChallenger{}, intelsgx.AttestationEpid); err != nil {
		fmt.Print(err)
	}
}
