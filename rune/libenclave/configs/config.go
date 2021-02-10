package configs // import "github.com/inclavare-containers/rune/libenclave/configs"

type InitEnclaveConfig struct {
	Type                  string `json:"type"`
	Path                  string `json:"path"`
	Args                  string `json:"args"`
	LogLevel              string `json:"loglevel"`
	RaType                string `json:"ra_type"`
	RaEpidSpid            string `json:"ra_epid_spid"`
	RaEpidSubscriptionKey string `json:"ra_epid_subscription_key"`
}

type EnclaveConfig struct {
	Enclave *Enclave `json:"Enclave,omitempty"`
}

// Define the types of enclave hardware
const (
	EnclaveTypeNone             string = ""
	EnclaveTypeIntelSgx         string = "intelSgx"
	EnclaveTypeAwsNitroEnclaves string = "AwsNitroEnclaves"
	EnclaveTypeJailHouse        string = "Jailhouse"
)

type Enclave struct {
	Type                  string `json:"type"`
	Path                  string `json:"path"`
	Args                  string `json:"args,omitempty"`
	LogLevel              string `json:"loglevel"`
	RaType                string `json:"ra_type,omitempty"`
	RaEpidSpid            string `json:"ra_epid_spid,omitempty"`
	RaEpidSubscriptionKey string `json:"ra_epid_subscription_key,omitempty"`
}

type IntelSgx struct {
	Sgx2Used bool `json:"sgx2,omitempty"`
}
