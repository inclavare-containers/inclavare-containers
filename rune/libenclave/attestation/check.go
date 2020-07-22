package attestation // import "github.com/opencontainers/runc/libenclave/attestation"

import (
	"fmt"
)

func (svc *Service) Check(q []byte) error {
	if q == nil {
		return fmt.Errorf("Invalid Quote")
	}

	return svc.Attester.Check(q)
}
