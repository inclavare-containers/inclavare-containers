package attestation // import "github.com/opencontainers/runc/libenclave/attestation"

import (
	"fmt"
)

type Challenger interface {
	Name() string
	New(map[string]string) error
	Check([]byte) error
	Verify([]byte) (*ReportStatus, error)
	GetReport([]byte, uint64) (*ReportStatus, map[string]string, error)
	ShowReportStatus(*ReportStatus)
	// TODO
	// PrepareChallenge() (*pb.AttestChallenge, error)
	// HandleChallengeResponse(*pb.AttestResponse) (*Quote, error)
}

type ReportStatus struct {
	StatusCode     uint32
	ErrorMessage   string
	SpecificStatus interface{}
}

/*
type Service struct {
	NonceForChallenge Nonce
	NonceForVerify    Nonce
}

type Quote struct {
	// FIXME: use interface like io.Reader as callback?
	Evidence []byte
}
*/

const (
	// FIXME: allow tuning via parameter
	seedTimeout int64 = 6e10 // 60 seconds
)

func NewChallenger(aType string, cfg map[string]string) (Challenger, error) {
	for _, c := range challengerList {
		if c.Name() == aType {
			if err := c.New(cfg); err != nil {
				return nil, err
			}

			return c, nil
		}
	}

	return nil, fmt.Errorf("Unsupported attestation service %s specified", aType)
}

var challengerList []Challenger

func registerChallenger(challenger Challenger) error {
	for _, c := range challengerList {
		if c.Name() == challenger.Name() {
			return fmt.Errorf("Attestation service %s registered already", challenger.Name())
		}
	}

	challengerList = append(challengerList, challenger)

	return nil
}

/*
func PrepareChallenger() (*pb.AttestChallenge, error) {
        return &pb.AttestChallenge{
                Nonce: NonceForChallenge.Generate(),
        }, nil
}

func HandleResponse(r *pb.AttestResponse) (*attest.Quote, error) {
        quote := r.GetQuote()

        if len(quote) <= intelsgx.QuoteLength {
                return nil, fmt.Errorf("Invalid length of quote returned: %d-byte", len(quote))
        }

        return &Quote{Evidence: quote}, nil
}
*/
