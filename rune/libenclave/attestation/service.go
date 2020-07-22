package attestation // import "github.com/opencontainers/runc/libenclave/attestation"

import (
	"fmt"
	pb "github.com/opencontainers/runc/libenclave/attestation/proto"
	"log"
)

type Service struct {
	Attester
	NonceForChallenge Nonce
	NonceForVerify    Nonce
	verbose           bool
}

type Attester interface {
	PrepareChallenge() (*pb.AttestChallenge, error)
	HandleChallengeResponse(r *pb.AttestResponse) (*Quote, error)
	Check([]byte) error
	Verify([]byte) *Status
	ShowStatus(status *Status)
}

type Quote struct {
	// FIXME: use interface like io.Reader as callback?
	Evidence []byte
}

const (
	StatusSgxBit = 0x80000000
)

type Status struct {
	StatusCode     uint32
	ErrorMessage   string
	SpecificStatus interface{}
}

func NewService(p map[string]string, verbose bool) (*Service, error) {
	// TODO: try to probe the hardware and know which hardware security
	// technology is actually supported.

	for _, reg := range registry {
		var svc *Service
		var err error

		if svc, err = reg.Create(p); err == nil {
			if svc.Attester == nil {
				log.Println("Attestation service not set attester")
				continue
			}

			svc.verbose = verbose
			return svc, nil
		}

		if verbose {
			log.Fatal(err)
		}
	}

	return nil, fmt.Errorf("No matching attestation registry available")
}

/*
func (attest *Attestation) SetParameter(key string, val string, overwrite bool) error {
	// FIXME: use sync mutex
	if err := attest.GetParameter(key); err == nil {
		if !overwrite {
			return fmt.Errorf("Attestation parameter %s exists", key)
		}
	}

	attest.parameters[key] = val

	return nil
}

func (attest *Attestation) GetParameter(key string) (string, error) {
	if !attest.parameters[key] {
		return "", fmt.Errorf("Attestation parameter %s not exists", key)
	}

	return attest.parameters[key], nil
}
*/

func (svc *Service) VerboseOn() {
	svc.verbose = true
}

func (svc *Service) VerboseOff() {
	svc.verbose = false
}

func (svc *Service) IsVerbose() bool {
	return svc.verbose
}
