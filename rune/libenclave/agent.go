package libenclave // import "github.com/inclavare-containers/rune/libenclave"

import (
	"fmt"
	pb "github.com/inclavare-containers/rune/libenclave/proto"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"strings"
)

const agentServicePath = "agent.sock"

var instanceId int

func CreateParentAgentPipe(root string, uid, gid int) (lnFile *os.File, err error) {
	// The Linux kernel only allows unix domain socket paths less than
	// 108 bytes, so chdir() to avoid errors caused by excessively long
	// path.
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if err = os.Chdir(root); err != nil {
		return nil, err
	}
	defer os.Chdir(cwd)

	ln, err := net.Listen("unix", agentServicePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			ln.Close()
		}
	}()
	unixListener, ok := ln.(*net.UnixListener)
	if !ok {
		return nil, fmt.Errorf("casting to UnixListener failed")
	}
	// By default the underlying socket file is removed when the
	// listener is closed, no matter what the opened file count is.
	// This behavior will cause the connection failure when the
	// incoming child runelet attempts to connect to agent service.
	unixListener.SetUnlinkOnClose(false)
	defer func() {
		if err != nil {
			unixListener.SetUnlinkOnClose(true)
		}
	}()
	lnFile, err = unixListener.File()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			lnFile.Close()
		}
	}()

	err = unix.Chmod(agentServicePath, 0622)
	if err != nil {
		return nil, err
	}
	err = os.Chown(agentServicePath, uid, gid)
	if err != nil {
		return nil, err
	}

	return lnFile, nil
}

func CreateChildAgentPipe(root string) (*os.File, error) {
	// Linux kernel only supports unix domain socket path with 108 characters,
	// and thus we have to use relative path with the assist of chdir().
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if err = os.Chdir(root); err != nil {
		return nil, err
	}
	defer os.Chdir(cwd)

	conn, err := net.Dial("unix", agentServicePath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("casting to UnixConn failed")
	}

	connFile, err := unixConn.File()
	if err != nil {
		return nil, err
	}
	return connFile, nil
}

func startAgentService(agentPipe *os.File, notifyExit <-chan struct{}) <-chan struct{} {
	isDead := make(chan struct{})
	go func() {
		defer close(isDead)

		ln, err := net.FileListener(agentPipe)
		if err != nil {
			return
		}
		defer ln.Close()
		uln, ok := ln.(*net.UnixListener)
		if !ok {
			return
		}

		for {
			select {
			case <-notifyExit:
				logrus.Debug("TODO: notifying exit event")
				return
			default:
			}

			client, err := uln.Accept()
			if err != nil {
				logrus.Debugf("accept() failed with %v", err)
				return
			}
			instanceId += 1
			go handleRequest(client, instanceId)
		}
	}()

	return isDead
}

func handleRequest(conn net.Conn, id int) {
	defer conn.Close()

	if enclaveRuntime == nil {
		logrus.Fatal("race with parent runelet")
		return
	}

	var err error
	resp := &pb.AgentServiceResponse{}
	exitCode := int32(1)

	req := &pb.AgentServiceRequest{}
	if err = protoBufRead(conn, req); err != nil {
		return
	}

	c, ok := conn.(*net.UnixConn)
	if !ok {
		err = fmt.Errorf("casting to UnixConn failed")
		return
	}
	connFile, err := c.File()
	if err != nil {
		return
	}
	defer connFile.Close()

	if req.Attest != nil {
		logrus.Infof("In function handleRequest: get an attest request")
		resp.Attest = &pb.AgentServiceResponse_Attest{}
		localReport, err := enclaveRuntime.LaunchAttestation(req.Attest.IsRA, req.Attest.QuoteType,
			req.Attest.Spid,
			req.Attest.SubscriptionKey)
		if err != nil {
			resp.Attest.Error = fmt.Sprint(err)
		} else {
			exitCode = 0
		}

		resp.Attest.ExitCode = exitCode
		resp.Attest.LocalReport = localReport

		protoBufWrite(conn, resp)
		return
	}

	resp.Exec = &pb.AgentServiceResponse_Execute{}
	defer func() {
		resp.Exec.ExitCode = exitCode
		if err != nil {
			resp.Exec.Error = fmt.Sprint(err)
		}
		protoBufWrite(conn, resp)
	}()

	// Retrieve signal pipe.
	signalPipe, err := utils.RecvFd(connFile)
	if err != nil {
		return
	}
	go relaySignal(signalPipe, id)

	// Retrieve stdio fds.
	stdin, err := utils.RecvFd(connFile)
	if err != nil {
		return
	}
	defer stdin.Close()
	stdout, err := utils.RecvFd(connFile)
	if err != nil {
		return
	}
	defer stdout.Close()
	stderr, err := utils.RecvFd(connFile)
	if err != nil {
		return
	}
	defer stderr.Close()
	stdio := [3]*os.File{
		stdin, stdout, stderr,
	}

	cmd := req.Exec.GetArgv()
	envp := req.Exec.GetEnvp()
	exitCode, err = enclaveRuntime.ExecutePayload(strings.Split(cmd, " "), strings.Split(envp, " "), stdio)
	if err != nil {
		return
	}

	// TODO: sync up with relaySignal()

	logrus.Debug("remote exec normally exits")
}

func relaySignal(signalPipe *os.File, id int) {
	defer signalPipe.Close()

	for {
		req := &pb.AgentServiceRequest{}
		if err := protoBufRead(signalPipe, req); err != nil {
			return
		}

		err := enclaveRuntime.KillPayload(id, int(req.Kill.Sig))
		if err != nil {
			logrus.Errorf("unable to kill payload with sig %d by %d: %v\n", int(req.Kill.Sig), id, err)
			return
		}
	}
}
