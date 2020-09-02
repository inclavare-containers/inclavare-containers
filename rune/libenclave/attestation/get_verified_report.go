package attestation // import "github.com/opencontainers/runc/libenclave/attestation"

func (svc *Service) GetVerifiedReport(q []byte) (*Status, map[string]string, error) {
	return svc.Attester.GetVerifiedReport(q)
}
