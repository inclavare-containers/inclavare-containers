package attestation // import "github.com/inclavare-containers/rune/libenclave/attestation"

import (
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/attestation/internal/registration"
	_ "github.com/inclavare-containers/rune/libenclave/attestation/internal/sgx/challenger" // for the registration of sgx challengers
)

type Challenger interface {
	Name() string
	New(map[string]string) error
	Check([]byte) error
	/* the return value significance of Verify(), GetReport(), and ShowReportStatus():
	   - uint32: statusCode
	   - interface{}: SpecificStatus
	*/
	Verify([]byte) (uint32, interface{}, error)
	GetReport([]byte, uint64) (uint32, interface{}, map[string]string, error)
	ShowReportStatus(uint32, interface{}) error
	// TODO
	// PrepareChallenge() (*pb.AttestChallenge, error)
	// HandleChallengeResponse(*pb.AttestResponse) (*Quote, error)
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
	for _, challenger := range registration.ChallengerRegisterationList {
		c := challenger.Registeration.(Challenger)
		if c.Name() == aType {
			if err := c.New(cfg); err != nil {
				return nil, err
			}

			return c, nil
		}
	}

	return nil, fmt.Errorf("Unsupported attestation service %s specified", aType)
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
