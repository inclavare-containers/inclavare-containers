package libenclave // import "github.com/inclavare-containers/rune/libenclave"

import (
	"encoding/json"
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/configs"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"github.com/inclavare-containers/rune/libenclave/internal/runtime"
	pb "github.com/inclavare-containers/rune/libenclave/proto"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

const signalBufferSize = 2048

var enclaveRuntime *runtime.EnclaveRuntimeWrapper

type RuneletConfig struct {
	InitPipe  *os.File
	LogFd     int
	LogLevel  string
	FifoFd    int
	AgentPipe *os.File
	Detached  bool
}

func StartInitialization(cmd []string, cfg *RuneletConfig) (exitCode int32, err error) {
	// Determine which type of runelet is initializing.
	fifoFd := cfg.FifoFd

	// Retrieve the init pipe fd to accomplish the enclave configuration
	// handshake as soon as possible with parent rune.
	initPipe := cfg.InitPipe
	defer func() {
		if err != nil {
			initPipe.Close()
		}
	}()
	if err = writeSync(initPipe, procEnclaveConfigReq); err != nil {
		return 1, err
	}
	var config *configs.InitEnclaveConfig
	if err = json.NewDecoder(initPipe).Decode(&config); err != nil {
		return 1, err
	}
	if err = writeSync(initPipe, procEnclaveConfigAck); err != nil {
		return 1, err
	}

	logLevel := configs.DefaultLogLevel
	if config.LogLevel != "" {
		logLevel = config.LogLevel
	}

	// Only parent runelet has a responsibility to initialize the enclave
	// runtime.

	var rt *runtime.EnclaveRuntimeWrapper
	if fifoFd != -1 {
		rt, err = runtime.StartInitialization(config, logLevel)
		if err != nil {
			return 1, err
		}
		if err = writeSync(initPipe, procEnclaveInit); err != nil {
			return 1, err
		}

		// Launch a remote attestation to the enclave runtime.
		if strings.EqualFold(config.RaType, intelsgx.QuoteTypeEpidUnlinkable) || strings.EqualFold(config.RaType, intelsgx.QuoteTypeEpidLinkable) {
			if _, err := rt.LaunchAttestation(true, config.RaType, config.RaEpidSpid, config.RaEpidSubscriptionKey); err != nil {
				return 1, err
			}
		}
		if err = readSync(initPipe, procEnclaveReady); err != nil {
			return 1, err
		}
	}

	// If runelet run as detach mode, close logrus before initpipe closed.
	if cfg.Detached {
		logrus.SetOutput(ioutil.Discard)
	}

	// Close the init pipe to signal that we have completed our init.
	// So `rune create` or the upper half part of `rune run` can return.
	initPipe.Close()

	// Take care the execution sequence among components. Closing exec fifo
	// made by finalizeInitialization() allows the execution of `rune start`
	// or the bottom half of `rune run` preempts the startup of agent service
	// and entrypoint, implying `rune exec` may preempt them too.

	// Launch agent service for child runelet.
	agentPipe := cfg.AgentPipe
	defer agentPipe.Close()

	notifySignal := make(chan os.Signal, signalBufferSize)

	if fifoFd == -1 {
		AttestCommand := os.Getenv("AttestCommand")
		if AttestCommand == "true" {
			logrus.Infof("Get an attest command")
			exitCode, err = remoteAttest(agentPipe, config, notifySignal)
			if err != nil {
				return exitCode, err
			}
			logrus.Debugf("remote attest normally exits")

			return exitCode, err
		} else {
			logrus.Infof("Get an exec command")
			exitCode, err = remoteExec(agentPipe, cmd, notifySignal)
			if err != nil {
				return exitCode, err
			}
			logrus.Debug("remote exec normally exits")

			return exitCode, err
		}
	}

	notifyExit := make(chan struct{})
	sigForwarderExit := forwardSignal(rt, notifySignal, notifyExit)
	agentExit := startAgentService(agentPipe, notifyExit)

	if err = finalizeInitialization(fifoFd); err != nil {
		return 1, err
	}

	// Capture all signals and then forward to enclave runtime.
	signal.Notify(notifySignal)

	// Set this variable **after** startAgentService() to ensure
	// child runelet cannot start up a payload prior to container
	// entrypoint launched by parent runelet. However, we still
	// have a way to prevent from this race happening.
	enclaveRuntime = rt

	exitCode, err = rt.ExecutePayload(cmd, os.Environ(),
		[3]*os.File{
			os.Stdin, os.Stdout, os.Stderr,
		})
	if err != nil {
		return exitCode, err
	}
	logrus.Debug("enclave runtime payload normally exits")

	notifyExit <- struct{}{}
	select {
	case <-agentExit:
		logrus.Debug("agent service exited")
	case <-sigForwarderExit:
		logrus.Debug("signal forwarder exited")
	}

	// The entrypoint payload exited, meaning current runelet process will die,
	// so friendly handle the exit path of enclave runtime instance.
	if err = rt.DestroyInstance(); err != nil {
		return exitCode, err
	}

	return exitCode, err
}

func forwardSignal(rt *runtime.EnclaveRuntimeWrapper, notifySignal <-chan os.Signal, notifyExit <-chan struct{}) <-chan struct{} {
	isDead := make(chan struct{})
	go func() {
		defer close(isDead)
		for {
			select {
			case <-notifyExit:
				return
			case sig := <-notifySignal:
				n := int(sig.(syscall.Signal))
				err := rt.KillPayload(-1, n)
				if err != nil {
					logrus.Debugf("failed to kill enclave runtime with signal %d", n)
				}
				// Allow to terminate the whole container through ctrl-C
				// in rune foreground mode.
				if sig == unix.SIGINT {
					os.Exit(0)
				}
			}
		}
	}()

	return isDead
}

func finalizeInitialization(fifoFd int) error {
	// Wait for the FIFO to be opened on the other side before exec-ing the
	// user process. We open it through /proc/self/fd/$fd, because the fd that
	// was given to us was an O_PATH fd to the fifo itself. Linux allows us to
	// re-open an O_PATH fd through /proc.
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", fifoFd), unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open exec fifo")
	}
	if _, err := unix.Write(fd, []byte("0")); err != nil {
		return fmt.Errorf("write 0 exec fifo")
	}
	// Close the O_PATH fifofd fd before exec because the kernel resets
	// dumpable in the wrong order. This has been fixed in newer kernels, but
	// we keep this to ensure CVE-2016-9962 doesn't re-emerge on older kernels.
	// N.B. the core issue itself (passing dirfds to the host filesystem) has
	// since been resolved.
	// https://github.com/torvalds/linux/blob/v4.9/fs/exec.c#L1290-L1318
	unix.Close(fifoFd)
	unix.Close(fd)
	return nil
}

func remoteAttest(agentPipe *os.File, config *configs.InitEnclaveConfig, notifySignal chan os.Signal) (exitCode int32, err error) {
	c, err := net.FileConn(agentPipe)
	if err != nil {
		return 1, err
	}
	defer c.Close()
	conn, ok := c.(*net.UnixConn)
	if !ok {
		return 1, fmt.Errorf("casting to UnixConn faild")
	}

	quoteType := os.Getenv("QUOTE_TYPE")
	if !strings.EqualFold(quoteType, intelsgx.QuoteTypeEpidUnlinkable) && strings.EqualFold(quoteType, intelsgx.QuoteTypeEpidLinkable) && strings.EqualFold(quoteType, intelsgx.QuoteTypeEcdsa) {
		return 1, fmt.Errorf("Unsupported Quote Type Configuration %v!\n", quoteType)
	}

	isRA := false
	if os.Getenv("IsRemoteAttestation") == "true" {
		logrus.Infof("preparing to remote Attest")
		isRA = true
	}

	req := &pb.AgentServiceRequest{}
	req.Attest = &pb.AgentServiceRequest_Attest{
		IsRA:            isRA,
		QuoteType:       quoteType,
		Spid:            os.Getenv("SPID"),
		SubscriptionKey: os.Getenv("SUBSCRIPTION_KEY"),
	}

	if err = protoBufWrite(conn, req); err != nil {
		return 1, err
	}

	agentFile, err := conn.File()
	if err != nil {
		return 1, err
	}
	defer agentFile.Close()

	// Send signal notification pipe.
	childSignalPipe, parentSignalPipe, err := os.Pipe()
	agentFile, err = conn.File()
	if err != nil {
		return 1, err
	}
	defer agentFile.Close()

	// Send signal notification pipe.
	childSignalPipe, parentSignalPipe, err = os.Pipe()
	if err != nil {
		return 1, err
	}
	defer func() {
		if err != nil {
			childSignalPipe.Close()
		}
		parentSignalPipe.Close()
	}()

	if err = utils.SendFd(agentFile, childSignalPipe.Name(), childSignalPipe.Fd()); err != nil {
		return 1, err
	}

	// Close the child signal pipe in parent side **after** sending all stdio fds to
	// make sure the parent runelet has retrieved the child signal pipe.
	childSignalPipe.Close()

	signal.Notify(notifySignal)

	notifyExit := make(chan struct{})
	sigForwarderExit := forwardSignalToParent(parentSignalPipe, notifySignal, notifyExit)

	resp := &pb.AgentServiceResponse{}
	if err = protoBufRead(conn, resp); err != nil {
		return 1, err
	}

	notifyExit <- struct{}{}
	logrus.Debug("awaiting for signal forwarder exiting ...")
	<-sigForwarderExit
	logrus.Debug("signal forwarder exited")

	if resp.Attest.Error == "" {
		err = nil
	} else {
		err = fmt.Errorf(resp.Attest.Error)
	}

	reportFile := os.Getenv("REPORT_FILE")
	if reportFile != "" {
		err := ioutil.WriteFile(reportFile, resp.Attest.LocalReport, 0664)
		if err != nil {
			return 1, err
		}

		logrus.Infof("target enclave's report file %s saved", reportFile)
	}

	return resp.Attest.ExitCode, err
}

func remoteExec(agentPipe *os.File, cmd []string, notifySignal chan os.Signal) (exitCode int32, err error) {
	c := strings.Join(cmd, " ")
	logrus.Debugf("preparing to remote exec %s", c)

	req := &pb.AgentServiceRequest{}
	req.Exec = &pb.AgentServiceRequest_Execute{
		Argv: c,
		Envp: strings.Join(os.Environ(), " "),
	}
	if err = protoBufWrite(agentPipe, req); err != nil {
		return 1, err
	}

	// Send signal notification pipe.
	childSignalPipe, parentSignalPipe, err := os.Pipe()
	if err != nil {
		return 1, err
	}
	defer func() {
		if err != nil {
			childSignalPipe.Close()
		}
		parentSignalPipe.Close()
	}()

	if err = utils.SendFd(agentPipe, childSignalPipe.Name(), childSignalPipe.Fd()); err != nil {
		return 1, err
	}

	// Send stdio fds.
	if err = utils.SendFd(agentPipe, os.Stdin.Name(), os.Stdin.Fd()); err != nil {
		return 1, err
	}
	if err = utils.SendFd(agentPipe, os.Stdout.Name(), os.Stdout.Fd()); err != nil {
		return 1, err
	}
	if err = utils.SendFd(agentPipe, os.Stderr.Name(), os.Stderr.Fd()); err != nil {
		return 1, err
	}
	// Close the child signal pipe in parent side **after** sending all stdio fds to
	// make sure the parent runelet has retrieved the child signal pipe.
	childSignalPipe.Close()

	signal.Notify(notifySignal)

	notifyExit := make(chan struct{})
	sigForwarderExit := forwardSignalToParent(parentSignalPipe, notifySignal, notifyExit)

	resp := &pb.AgentServiceResponse{}
	if err = protoBufRead(agentPipe, resp); err != nil {
		return 1, err
	}

	notifyExit <- struct{}{}
	logrus.Debug("awaiting for signal forwarder exiting ...")
	<-sigForwarderExit
	logrus.Debug("signal forwarder exited")

	if resp.Exec.Error == "" {
		err = nil
	} else {
		err = fmt.Errorf(resp.Exec.Error)
	}
	return resp.Exec.ExitCode, err
}

func forwardSignalToParent(conn io.Writer, notifySignal chan os.Signal, notifyExit <-chan struct{}) <-chan struct{} {
	isDead := make(chan struct{})
	go func() {
		defer close(isDead)

		for {
			select {
			case <-notifyExit:
				logrus.Debug("signal forwarder notified to exit")
				// TODO: terminate this child runelet.
				return
			case sig := <-notifySignal:
				n := int32(sig.(syscall.Signal))
				req := &pb.AgentServiceRequest{}
				req.Kill = &pb.AgentServiceRequest_Kill{
					Sig: n,
				}
				if err := protoBufWrite(conn, req); err != nil {
					logrus.Errorf("failed to send kill request with signal %d", n)
				}

				// Allow to terminate the whole container through ctrl-C
				// in rune foreground mode.
				if sig == unix.SIGINT {
					os.Exit(0)
				}
			}
		}
	}()

	return isDead
}
