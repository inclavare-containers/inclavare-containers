package configs

// Define the types of enclave hardware
const (
	EnclaveHwDefault  string = ""
	EnclaveHwIntelSgx string = "intelSgx"
)

type Enclave struct {
	Type string `json:"type"`
	Path string `json:"path"`
	Args string `json:"args,omitempty"`
}
