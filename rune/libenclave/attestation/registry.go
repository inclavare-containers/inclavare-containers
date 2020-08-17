package attestation // import "github.com/inclavare-containers/rune/libenclave/attestation"

var registry []Registry

type Registry interface {
	Create(p map[string]string) (*Service, error)
}

func RegisterAttestation(reg Registry) error {
	// FIXME: check re-register
	registry = append(registry, reg)

	return nil
}
