package configs // import "github.com/opencontainers/runc/libenclave/configs"

type InitEnclaveConfig struct {
	Type                  string `json:"type"`
	Path                  string `json:"path"`
	Args                  string `json:"args"`
	RaType                string `json:"ra_type"`
	RaEpidSpid            string `json:"ra_epid_spid"`
	RaEpidSubscriptionKey string `json:"ra_epid_subscription_key"`
	RaEpidQuoteType       string `json:"ra_epid_quote_type"`
}
