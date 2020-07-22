package attestation // import "github.com/opencontainers/runc/libenclave/attestation"

const (
	// FIXME: allow tuning via parameter
	seedTimeout int64 = 6e10 // 60 seconds
)

func (svc *Service) Verify(q []byte) *Status {
	return svc.Attester.Verify(q)
}
