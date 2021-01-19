package main // import "github.com/inclavare-containers/sgx-tools"

type attestationKeyIdentity struct {
	Id             uint16    `struct:"uint16,little"`
	Version        uint16    `struct:"uint16,little"`
	MrsignerLength uint16    `struct:"uint16,little"`
	Mrsigner       [48]uint8 `struct:"[48]uint8"`
	ProdId         uint32    `struct:"uint32,little"`
	ExtendedProdId [16]uint8 `struct:"[16]uint8"`
	ConfigId       [64]uint8 `struct:"[64]uint8"`
	FamilyId       [16]uint8 `struct:"[16]uint8"`
	AlgorithmId    uint32    `struct:"uint32,little"`
}

const (
	// EPID 2.0 - Anonymous
	sgxQuoteLibraryAlgorithmEpid = 0
	// Reserved
	sgxQuoteLibraryAlgorithmReseverd1 = 1
	// ECDSA-256-with-P-256 curve, Non - Anonymous
	sgxQuoteLibraryAlgorithmEcdsaP256 = 2
	// ECDSA-384-with-P-384 curve (Note: currently not supported), Non-Anonymous
	sgxQuoteLibraryAlgorithmEcdsaP384 = 3
	sgxQuoteLibraryAlgorithmMax       = 4
)

const (
	quoteTypeEcdsa          = "ecdsa"
	quoteTypeEpidUnlinkable = "epidUnlinkable"
	quoteTypeEpidLinkable   = "epidLinkable"
)
