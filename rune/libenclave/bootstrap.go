package libenclave // import "github.com/opencontainers/runc/libenclave"

import (
	"github.com/sirupsen/logrus"
	"os"
	"strconv"
)

// `rune init` needs to execute self (/proc/self/exe) in container environment
// as `runc init` executes entrypoint. Thus, some internal states in form of
// environment variable must be staged and then recovered after re-exec. This
// process is so called as libenclave bootstrapping, and the resulting process
// is so called as runelet.
func StartBootstrap(initPipe *os.File, logPipe *os.File, logLevel string, fifoFd int, agentPipe *os.File) (err error) {
	logrus.Debug("bootstrapping libenclave ...")

	if err = stageFd("_LIBENCLAVE_INITPIPE", initPipe); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			unstageFd("_LIBENCLAVE_INITPIPE")
		}
	}()

	if fifoFd != -1 {
		if err = stageFd("_LIBENCLAVE_FIFOFD", fifoFd); err != nil {
			return err
		}
		defer func() {
			if err != nil {
				unstageFd("_LIBENCLAVE_FIFOFD")
			}
		}()
	}

	envDetach := os.Getenv("_LIBENCLAVE_DETACH")

	detach, err := strconv.Atoi(envDetach)
	if err != nil || detach == 0 {
		if err = stageFd("_LIBENCLAVE_LOGPIPE", logPipe); err != nil {
			return err
		}
	}
	defer func() {
		if err != nil {
			unstageFd("_LIBENCLAVE_LOGPIPE")
		}
	}()

	if err = os.Setenv("_LIBENCLAVE_LOGLEVEL", logLevel); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Unsetenv("_LIBENCLAVE_LOGLEVEL")
		}
	}()

	if err = stageFd("_LIBENCLAVE_AGENTPIPE", agentPipe); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			unstageFd("_LIBENCLAVE_AGENTPIPE")
		}
	}()

	return nil
}
