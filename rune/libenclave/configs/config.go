package configs // import "github.com/opencontainers/runc/libenclave/configs"

type InitEnclaveConfig struct {
	Type                  string `json:"type"`
	Path                  string `json:"path"`
	Args                  string `json:"args"`
	RaType                uint32 `json:"ra_type"`
	RaEpidSpid            string `json:"ra_epid_spid"`
	RaEpidSubscriptionKey string `json:"ra_epid_subscription_key"`
	RaEpidIsLinkable      uint32 `json:"ra_epid_is_linkable"`
}
