package configs // import "github.com/inclavare-containers/rune/libenclave/configs"

const (
	DefaultLogLevel = "info"
)

var (
	// the log level of enclave runtime is inherited from runc --loglevel option
	LogLevelArray = []string{"trace", "debug", "info", "warning", "error", "fatal", "panic", "off"}
)
