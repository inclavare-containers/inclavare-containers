package attestation // import "github.com/inclavare-containers/rune/libenclave/attestation"

import (
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/attestation/internal/registration"
	_ "github.com/inclavare-containers/rune/libenclave/attestation/internal/sgx/attester" // for the registration of sgx attesters
)

type Attester interface {
	Name() string
	New(map[string]string) error
	GetTargetInfo() ([]byte, error)
	GetQuote([]byte) ([]byte, error)
}

func NewAttester(aType string, cfg map[string]string) (Attester, error) {
	for _, attester := range registration.AttesterRegisterationList {
		a := attester.Registeration.(Attester)
		if a.Name() == aType {
			if err := a.New(cfg); err != nil {
				return nil, err
			}

			return a, nil
		}
	}

	return nil, fmt.Errorf("Unsupported attestation service %s specified", aType)
}
