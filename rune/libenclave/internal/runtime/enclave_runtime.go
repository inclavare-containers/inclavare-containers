package runtime // import "github.com/inclavare-containers/rune/libenclave/internal/runtime"

import (
	"github.com/inclavare-containers/rune/libenclave/configs"
	core "github.com/inclavare-containers/rune/libenclave/internal/runtime/core"
	pal "github.com/inclavare-containers/rune/libenclave/internal/runtime/pal"
	"github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"strings"
)

type EnclaveRuntime interface {
	Init(args string, logLevel string) error
	Attest(bool, string, string, string) ([]byte, error)
	Exec(cmd []string, envp []string, stdio [3]*os.File) (int32, error)
	Kill(sig int, pid int) error
	Destroy() error
}

type EnclaveRuntimeWrapper struct {
	runtime EnclaveRuntime
}

func StartInitialization(config *configs.InitEnclaveConfig, logLevel string) (*EnclaveRuntimeWrapper, error) {
	logrus.Debugf("enclave init config retrieved: %+v", config)

	var (
		runtime EnclaveRuntime
		err     error
	)
	runtime, err = core.StartInitialization(config)
	if err != nil {
		runtime, err = pal.StartInitialization(config)
		if err != nil {
			return nil, err
		}
	}

	logrus.Infof("Initializing enclave runtime")
	err = runtime.Init(config.Args, logLevel)
	if err != nil {
		return nil, err
	}

	rt := &EnclaveRuntimeWrapper{
		runtime: runtime,
	}
	return rt, nil
}

func (rt *EnclaveRuntimeWrapper) LaunchAttestation(isRA bool, quoteType string, spid string, subscriptionKey string) ([]byte, error) {
	logrus.Debugf("attesting enclave runtime")

	return rt.runtime.Attest(isRA, quoteType, spid, subscriptionKey)
}

func (rt *EnclaveRuntimeWrapper) ExecutePayload(cmd []string, envp []string, stdio [3]*os.File) (int32, error) {
	logrus.Debugf("enclave runtime %s executing payload with commandline", strings.Join(cmd, " "))

	// The executable may not exist in container at all according
	// to the design of enclave runtime, such as Occlum, which uses
	// an invisible filesystem to the container. In this case, the
	// lookup will fail.
	if fullPath, err := exec.LookPath(cmd[0]); err == nil {
		cmd[0] = fullPath
	}
	return rt.runtime.Exec(cmd, envp, stdio)
}

func (rt *EnclaveRuntimeWrapper) KillPayload(pid int, sig int) error {
	if pid != -1 {
		logrus.Debugf("enclave runtime killing payload %d with signal %d", pid, sig)
	} else {
		logrus.Debugf("enclave runtime killing all payloads with signal %d", sig)
	}

	return rt.runtime.Kill(pid, sig)
}

func (rt *EnclaveRuntimeWrapper) DestroyInstance() error {
	logrus.Debugf("Destroying enclave runtime")

	return rt.runtime.Destroy()
}
