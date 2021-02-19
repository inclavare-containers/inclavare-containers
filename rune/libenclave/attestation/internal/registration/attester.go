package registration // import "github.com/inclavare-containers/rune/libenclave/attestation/internal/registeration

import (
	"fmt"
)

type AttesterRegisterationInfo struct {
	Name          string
	Registeration interface{}
}

var AttesterRegisterationList []AttesterRegisterationInfo

func RegisterAttester(attester interface{}, name string) error {
	if name == "" {
		return fmt.Errorf("Attester name couldn't be empty :%s", name)
	}

	for _, a := range AttesterRegisterationList {
		if a.Name == name {
			return fmt.Errorf("Attestation service: %s registered already", name)
		}
	}

	attesterRegInfo := AttesterRegisterationInfo{
		Name:          name,
		Registeration: attester,
	}

	AttesterRegisterationList = append(AttesterRegisterationList, attesterRegInfo)

	return nil
}
