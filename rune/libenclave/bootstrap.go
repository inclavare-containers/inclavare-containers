package libenclave // import "github.com/opencontainers/runc/libenclave"

import (
	"github.com/sirupsen/logrus"
	"os"
)

type enclaveRuntimeEnv struct {
	initPipe *os.File
	logPipe *os.File
	logLevel string
	fifoFd int
	agentPipe *os.File
	detached string
}

var enclaveEnv enclaveRuntimeEnv

func GetEnclaveRunetimeEnv() *enclaveRuntimeEnv {
	return &enclaveEnv
}

// `rune init` needs to execute self (/proc/self/exe) in container environment
// as `runc init` executes entrypoint. Thus, some internal states in form of
// environment variable must be staged and then recovered after re-exec. This
// process is so called as libenclave bootstrapping, and the resulting process
// is so called as runelet.
func StartBootstrap(initPipe *os.File, logPipe *os.File, logLevel string, fifoFd int, agentPipe *os.File, detached string) (err error) {
	logrus.Debug("bootstrapping libenclave ...")

	enclaveEnv.initPipe = initPipe
	enclaveEnv.logPipe = logPipe
	enclaveEnv.logLevel = logLevel
	enclaveEnv.fifoFd = fifoFd
	enclaveEnv.agentPipe = agentPipe
	enclaveEnv.detached = detached

	return nil
}
