package rune

import (
	"errors"
)

type CarrierKind string

const (
	Empty    CarrierKind = ""
	Occlum   CarrierKind = "occlum"
	Graphene CarrierKind = "graphene"
)

var ErrorUnknownCarrier = errors.New("unknown carrier")
