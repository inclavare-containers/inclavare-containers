package attestation // import "github.com/inclavare-containers/rune/libenclave/attestation"

import (
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/attestation/sgx/ias"
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
	return "sgx-epid"
}

func (epid *sgxEpidChallenger) New(cfg map[string]string) error {
	ias, err := ias.NewIasAttestation(cfg)
	if err != nil {
		return nil
	}
	epid.ias = ias

	return nil
}

func (epid *sgxEpidChallenger) Check(quote []byte) error {
	return epid.ias.CheckQuote(quote)
}

func (epid *sgxEpidChallenger) Verify(quote []byte) (*ReportStatus, error) {
	s, err := epid.ias.VerifyQuote(quote)
	if err != nil {
		return nil, err
	}

	/* FIXME: check whether the report status is acceptable */
	status := &ReportStatus{
		StatusCode:     StatusSgxBit,
		SpecificStatus: s,
	}

	return status, nil
}

func (epid *sgxEpidChallenger) GetReport(quote []byte, nonce uint64) (*ReportStatus, map[string]string, error) {
	s, report, err := epid.ias.RetrieveIasReport(quote, nonce)
	if err != nil {
		return nil, nil, err
	}

	status := &ReportStatus{
		StatusCode:     StatusSgxBit,
		SpecificStatus: s,
	}

	return status, report, nil
}

func (epid *sgxEpidChallenger) ShowReportStatus(status *ReportStatus) {
	if status.StatusCode&StatusSgxBit != StatusSgxBit {
		logrus.Error("Report status is used for SGX EPID-based")
		return
	}

	s, ok := status.SpecificStatus.(*ias.IasReportStatus)
	if ok {
		logrus.Infof("Request ID: %s\n", s.RequestId)
		logrus.Infof("Report ID: %s\n", s.ReportId)
		logrus.Infof("Timestamp: %s\n", s.Timestamp)
		logrus.Infof("IsvEnclaveQuoteStatus: %s\n", s.QuoteStatus)
	}
}

func init() {
	if err := registerChallenger(&sgxEpidChallenger{}); err != nil {
		fmt.Print(err)
	}
}
