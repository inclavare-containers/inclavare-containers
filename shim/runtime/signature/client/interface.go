package client

type Signature interface {
	Sign() error
	GetCertificate() (string, error)
}
