package sgx_attester // import "github.com/inclavare-containers/rune/libenclave/attestation/internal/sgx/attester"

import (
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/attestation/internal/registration"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
)

type sgxEcdsaAttester struct {
}

func (ecdsa *sgxEcdsaAttester) Name() string {
	return intelsgx.AttestationEcdsa
}

func (ecdsa *sgxEcdsaAttester) New(cfg map[string]string) error {
	return nil
}

func (ecdsa *sgxEcdsaAttester) GetTargetInfo() ([]byte, error) {
	targetInfo, err := intelsgx.GetQeTargetInfoEx(intelsgx.QuoteTypeEcdsa)

	return targetInfo, err
}

func (attester *sgxEcdsaAttester) GetQuote(report []byte) ([]byte, error) {
	quote, err := intelsgx.GetQuoteEx(intelsgx.QuoteTypeEcdsa, report, "")

	return quote, err
}

func init() {
	if err := registration.RegisterAttester(&sgxEcdsaAttester{}, intelsgx.AttestationEcdsa); err != nil {
		fmt.Print(err)
	}
}
