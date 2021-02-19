package registration // import "github.com/inclavare-containers/rune/libenclave/attestation/internal/registeration"

import (
	"fmt"
)

type ChallengerRegisterationInfo struct {
	Name          string
	Registeration interface{}
}

var ChallengerRegisterationList []ChallengerRegisterationInfo

func RegisterChallenger(challenger interface{}, name string) error {
	if name == "" {
		return fmt.Errorf("Challenger name couldn't be empty :%s", name)
	}

	for _, c := range ChallengerRegisterationList {
		if c.Name == name {
			return fmt.Errorf("Attestation service %s registered already", name)
		}
	}

	challengerRegInfo := ChallengerRegisterationInfo{
		Name:          name,
		Registeration: challenger,
	}

	ChallengerRegisterationList = append(ChallengerRegisterationList, challengerRegInfo)

	return nil
}
