package configs

// Define the types of enclave hardware
const (
	EnclaveHwDefault  string = ""
	EnclaveHwIntelSgx string = "intelSgx"
)

type Enclave struct {
	Type                  string `json:"type"`
	Path                  string `json:"path"`
	Args                  string `json:"args,omitempty"`
	RaType                string `json:"ra_type,omitempty"`
	RaEpidSpid            string `json:"ra_epid_spid,omitempty"`
	RaEpidSubscriptionKey string `json:"ra_epid_subscription_key,omitempty"`
	RaEpidQuoteType       string `json:"ra_epid_quote_type,omitempty"`
}
