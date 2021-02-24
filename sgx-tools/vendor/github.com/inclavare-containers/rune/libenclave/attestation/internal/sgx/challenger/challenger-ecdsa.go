package sgx_challenger // import "github.com/inclavare-containers/rune/libenclave/attestation/internal/sgx/challenger"

import (
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/attestation/internal/registration"
	"github.com/inclavare-containers/rune/libenclave/attestation/internal/sgx/dcap"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"unsafe"
)

type sgxEcdsaChallenger struct {
}

func (ecdsa *sgxEcdsaChallenger) Name() string {
	return intelsgx.AttestationEcdsa
}

func (ecdsa *sgxEcdsaChallenger) New(cfg map[string]string) error {
	return nil
}

func (ecdsa *sgxEcdsaChallenger) Check(quote []byte) error {
	if len(quote) < intelsgx.SgxEcdsaMinQuoteLength {
		return fmt.Errorf("len(quote) must be not less than %d", intelsgx.SgxEcdsaMinQuoteLength)
	}

	err := intelsgx.DumpQuote(quote)
	if err != nil {
		return err
	}

	q := (*intelsgx.Quote)(unsafe.Pointer(&quote[0]))

	if q.Version != intelsgx.QuoteVersion2 && q.Version != intelsgx.QuoteVersion3 {
		return fmt.Errorf("Unsupported quote version: %d", q.Version)
	}

	if q.SignatureType != intelsgx.QuoteSignatureTypeEcdsaP256 &&
		q.SignatureType != intelsgx.QuoteSignatureTypeEcdsaP384 {
		return fmt.Errorf("Unsupported signature type: %#04x", q.SignatureType)
	}

	return nil
}

func (ecdsa *sgxEcdsaChallenger) Verify(quote []byte) (uint32, interface{}, error) {
	err := dcap.VerifyEcdsaQuote(quote)

	return 0, nil, err
}

func (ecdsa *sgxEcdsaChallenger) GetReport(quote []byte, nonce uint64) (uint32, interface{}, map[string]string, error) {
	return 0, nil, nil, nil
}

func (ecdsa *sgxEcdsaChallenger) ShowReportStatus(statusCode uint32, specificStatus interface{}) error {
	return nil
}

func init() {
	if err := registration.RegisterChallenger(&sgxEcdsaChallenger{}, intelsgx.AttestationEcdsa); err != nil {
		fmt.Print(err)
	}
}
