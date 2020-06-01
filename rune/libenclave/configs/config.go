package configs // import "github.com/opencontainers/runc/libenclave/configs"

type InitEnclaveConfig struct {
	Type string   `json:"type"`
	Path string   `json:"path"`
	Args string   `json:"args"`
	Signer string `json:"signer"`
	Cmd  []string `json:"cmd"`
}
