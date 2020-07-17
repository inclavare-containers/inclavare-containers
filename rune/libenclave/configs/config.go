package configs // import "github.com/opencontainers/runc/libenclave/configs"

type InitEnclaveConfig struct {
	Type              string `json:"type"`
	Path              string `json:"path"`
	Args              string `json:"args"`
	RaType		  string `json:"ra_type"`
	RaSpid            string `json:"ra_spid"`
	RaSubscriptionKey string `json:"ra_subscription_key"`
	RaQuoteType       string `json:"ra_quote_type"`
}
