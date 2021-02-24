package ias // import "github.com/inclavare-containers/rune/libenclave/attestation/sgx/internal/ias"

const (
	apiV3 = 3
	apiV4 = 4
)

var (
	apiVersion uint64 = apiV4
)

type evidencePayload struct {
	IsvEnclaveQuote string `json:"isvEnclaveQuote"`
	PseManifest     string `json:"pseManifest,omitempty"`
	Nonce           string `json:"nonce,omitempty"`
}

type verificationReport struct {
	Id                    string `json:"id"`
	Timestamp             string `json:"timestamp"`
	Version               uint32 `json:"version"`
	IsvEnclaveQuoteStatus string `json:"isvEnclaveQuoteStatus"`
	IsvEnclaveQuoteBody   string `json:"isvEnclaveQuoteBody"`
	RevocationReason      uint32 `json:"revocationReason,omitempty"`
	PseManifestStatus     string `json:"pseManifestStatus,omitempty"`
	PseManifestHash       string `json:"pseManifestHash,omitempty"`
	PlatformInfoBlob      string `json:"platformInfoBlob,omitempty"`
	Nonce                 string `json:"nonce,omitempty"`
	EpidPseudonym         string `json:"epidPseudonym,omitempty"`

	// V4 fields
	AdvisoryIds string   `json:"advisoryURL,omitempty"`
	AdvisoryUrl []string `json:"advisoryIDs,omitempty"`
}
