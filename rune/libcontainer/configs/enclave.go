package configs

// Define the types of enclave hardware
const (
	EnclaveHwDefault  string = ""
	EnclaveHwIntelSgx string = "intelSgx"
)

type Enclave struct {
	Type              string `json:"type"`
	Path              string `json:"path"`
	Args              string `json:"args,omitempty"`
	RaType		  string `json:"ra_type,omitempty"`
	RaSpid            string `json:"ra_spid,omitempty"`
	RaSubscriptionKey string `json:"ra_subscription_key,omitempty"`
	RaQuoteType       string `json:"ra_quote_type,omitempty"`
}
