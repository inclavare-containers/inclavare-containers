package runtime // import "github.com/inclavare-containers/rune/libenclave/internal/runtime"

import (
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/configs"
	"github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"strings"
)

var runtimes = make(map[string]EnclaveRuntime)

func RuntimeRegister(name string, rt EnclaveRuntime) {
	runtimes[name] = rt
}

func RuntimeUnregister(name string) {
	delete(runtimes, name)
}

type EnclaveRuntime interface {
	Version() int32
	Capability() uint32
	Create(loglevel string, args string) (string, error)
	Delete(id string) error
	Init(id string) error
	Spawn(id string, args string) (int, error)
	Exec(id string, pid int, args []string, envp []string, stdio [3]*os.File) error
	Kill(id string, pid int, sig int) error
	Attest(id string) error
}

type EnclaveRuntimeWrapper struct {
	runtime   EnclaveRuntime
	enclaveId string
}

func StartInitialization(config *configs.InitEnclaveConfig, logLevel string) (*EnclaveRuntimeWrapper, error) {
	logrus.Debugf("enclave init config retrieved: %+v", config)

	for name, runtime := range runtimes {
		if config.Type == name {
			logrus.Infof("Initializing enclave runtime")
			enclaveId, err := runtime.Create(logLevel, config.Args)
			if err != nil {
				return nil, err
			}

			rt := &EnclaveRuntimeWrapper{
				runtime:   runtime,
				enclaveId: enclaveId,
			}
			return rt, nil
		}
	}
	return nil, fmt.Errorf("Unknown enclave type")
}

func (rt *EnclaveRuntimeWrapper) LaunchAttestation(isRA bool, spid string, subscriptionKey string, quoteType uint32) ([]byte, error) {
	logrus.Debugf("attesting enclave runtime")

	return nil, rt.runtime.Attest(rt.enclaveId /*, isRA, spid, subscriptionKey, quoteType*/)
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
	err := rt.runtime.Exec(rt.enclaveId, -1, cmd, envp, stdio)
	if err != nil {
		return -1, err
	}
	return 0, nil
}

func (rt *EnclaveRuntimeWrapper) KillPayload(pid int, sig int) error {
	if pid != -1 {
		logrus.Debugf("enclave runtime killing payload %d with signal %d", pid, sig)
	} else {
		logrus.Debugf("enclave runtime killing all payloads with signal %d", sig)
	}

	return rt.runtime.Kill(rt.enclaveId, pid, sig)
}

func (rt *EnclaveRuntimeWrapper) DestroyInstance() error {
	logrus.Debugf("Destroying enclave runtime")

	return rt.runtime.Delete(rt.enclaveId)
}
