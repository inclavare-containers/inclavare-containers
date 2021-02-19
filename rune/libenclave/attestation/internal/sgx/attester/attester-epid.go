package sgx_attester // import "github.com/inclavare-containers/rune/libenclave/attestation/internal/sgx/attester"

import (
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/attestation/internal/registration"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"strings"
)

type sgxEpidAttester struct {
	spid     string
	linkable bool
}

func (epid *sgxEpidAttester) Name() string {
	return intelsgx.AttestationEpid
}

func (epid *sgxEpidAttester) New(cfg map[string]string) error {
	spid, ok := cfg["spid"]
	if !ok || spid == "" {
		return fmt.Errorf("EPID parameter spid not specified")
	}

	if len(spid) != intelsgx.SpidLength*2 {
		return fmt.Errorf("spid must be %d-character long", intelsgx.SpidLength*2)
	}

	linkable, ok := cfg["linkable"]
	if !ok || linkable == "" {
		return fmt.Errorf("epid linkable parameter is not specified")
	}

	if strings.EqualFold(linkable, "linkable") {
		epid.linkable = true
	} else if strings.EqualFold(linkable, "unlinkable") {
		epid.linkable = false
	} else {
		return fmt.Errorf("Unsupport epid quote type")
	}

	epid.spid = spid

	return nil
}

func (epid *sgxEpidAttester) GetTargetInfo() ([]byte, error) {
	quoteType := intelsgx.QuoteTypeEpidUnlinkable
	if epid.linkable {
		quoteType = intelsgx.QuoteTypeEpidLinkable
	}

	targetInfo, err := intelsgx.GetQeTargetInfoEx(quoteType)

	return targetInfo, err
}

func (epid *sgxEpidAttester) GetQuote(report []byte) ([]byte, error) {
	quoteType := intelsgx.QuoteTypeEpidUnlinkable
	if epid.linkable {
		quoteType = intelsgx.QuoteTypeEpidLinkable
	}

	quote, err := intelsgx.GetQuoteEx(quoteType, report, epid.spid)

	return quote, err
}

func init() {
	if err := registration.RegisterAttester(&sgxEpidAttester{}, intelsgx.AttestationEpid); err != nil {
		fmt.Print(err)
	}
}
