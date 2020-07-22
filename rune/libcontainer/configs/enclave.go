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
	RaType                uint32 `json:"ra_type,omitempty"`
	RaEpidSpid            string `json:"ra_epid_spid,omitempty"`
	RaEpidSubscriptionKey string `json:"ra_epid_subscription_key,omitempty"`
	RaEpidIsLinkable      uint32 `json:"ra_epid_is_linkable,omitempty"`
}
