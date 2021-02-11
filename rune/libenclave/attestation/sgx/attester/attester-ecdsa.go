package sgx_attester // import "github.com/inclavare-containers/rune/libenclave/attestation/sgx/attester"

import (
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/attestation/registration"
	"github.com/inclavare-containers/rune/libenclave/attestation/sgx"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
)

type sgxEcdsaAttester struct {
}

func (ecdsa *sgxEcdsaAttester) Name() string {
	return sgx.AttestationEcdsa
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
	if err := registration.RegisterAttester(&sgxEcdsaAttester{}, sgx.AttestationEcdsa); err != nil {
		fmt.Print(err)
	}
}
