package client

import (
	"context"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"

	agentgrpc "github.com/confidential-containers/enclave-cc/shim/runtime/v2/rune/agent/grpc"
	"github.com/containerd/ttrpc"
)

var defaultDialTimeout = 30 * time.Second

var agentClientFields = logrus.Fields{
	"name":   "agent-client",
	"pid":    os.Getpid(),
	"source": "agent-client",
}

const (
	UnixSocketScheme = "unix"
	TcpSocketScheme  = "tcp"
)

var agentClientLog = logrus.WithFields(agentClientFields)

// AgentClient is an agent gRPC client connection wrapper for agentgrpc.AgentServiceClient
type AgentClient struct {
	ImageServiceClient agentgrpc.ImageService
	conn               *ttrpc.Client
}

// NewAgentClient creates a new agent gRPC client and handles both unix and tcp addresses.
//
// Supported sock address formats are:
//   - unix://<path>
//   - tcp://<ip>:<port>
func NewAgentClient(ctx context.Context, sock string, timeout uint32) (*AgentClient, error) {
	grpcAddr, parsedAddr, err := parse(sock)
	if err != nil {
		return nil, err
	}

	dialTimeout := defaultDialTimeout
	if timeout > 0 {
		dialTimeout = time.Duration(timeout) * time.Second
		agentClientLog.WithField("timeout", timeout).Debug("custom dialing timeout has been set")
	}

	var conn net.Conn
	var d = agentDialer(parsedAddr)
	conn, err = d(grpcAddr, dialTimeout)
	if err != nil {
		return nil, err
	}

	client := ttrpc.NewClient(conn)

	return &AgentClient{
		ImageServiceClient: agentgrpc.NewImageClient(client),
		conn:               client,
	}, nil
}

type dialer func(string, time.Duration) (net.Conn, error)

// Close an existing connection to the agent gRPC server.
func (c *AgentClient) Close() error {
	return c.conn.Close()
}

func parse(sock string) (string, *url.URL, error) {
	addr, err := url.Parse(sock)
	if err != nil {
		return "", nil, err
	}

	var grpcAddr string
	// validate more
	switch addr.Scheme {
	case UnixSocketScheme:
		if addr.Path == "" {
			return "", nil, grpcStatus.Errorf(codes.InvalidArgument, "Invalid unix sock scheme: %s", sock)
		}
		// e.g. unix:///tmp/socket
		grpcAddr = UnixSocketScheme + ":" + addr.Path
	case TcpSocketScheme:
		if addr.Host == "" {
			return "", nil, grpcStatus.Errorf(codes.InvalidArgument, "Invalid tcp sock scheme: %s", sock)
		}
		// e.g. tcp://ip:port
		grpcAddr = TcpSocketScheme + ":" + addr.Host
	default:
		return "", nil, grpcStatus.Errorf(codes.InvalidArgument, "Invalid scheme: %s", sock)
	}

	return grpcAddr, addr, nil
}

func agentDialer(addr *url.URL) dialer {
	switch addr.Scheme {
	case UnixSocketScheme:
		return UnixDialer
	case TcpSocketScheme:
		return TcpDialer
	default:
		return nil
	}
}

// This would bypass the grpc dialer backoff strategy and handle dial timeout
// internally. Because we do not have a large number of concurrent dialers,
// it is not reasonable to have such aggressive backoffs which would kill kata
// containers boot up speed. For more information, see
// https://github.com/grpc/grpc/blob/master/doc/connection-backoff.md
func commonDialer(timeout time.Duration, dialFunc func() (net.Conn, error), timeoutErrMsg error) (net.Conn, error) {
	t := time.NewTimer(timeout)
	cancel := make(chan bool)
	ch := make(chan net.Conn)
	go func() {
		for {
			select {
			case <-cancel:
				// canceled or channel closed
				return
			default:
			}

			conn, err := dialFunc()
			if err == nil {
				// Send conn back iff timer is not fired
				// Otherwise there might be no one left reading it
				if t.Stop() {
					ch <- conn
				} else {
					conn.Close()
				}
				return
			}
		}
	}()

	var conn net.Conn
	var ok bool
	select {
	case conn, ok = <-ch:
		if !ok {
			return nil, timeoutErrMsg
		}
	case <-t.C:
		cancel <- true
		return nil, timeoutErrMsg
	}

	return conn, nil
}

func UnixDialer(sock string, timeout time.Duration) (net.Conn, error) {
	sock = strings.TrimPrefix(sock, "unix:")

	dialFunc := func() (net.Conn, error) {
		return net.DialTimeout("unix", sock, timeout)
	}

	timeoutErr := grpcStatus.Errorf(codes.DeadlineExceeded, "timed out connecting to unix socket %s", sock)
	return commonDialer(timeout, dialFunc, timeoutErr)
}

func TcpDialer(sock string, timeout time.Duration) (net.Conn, error) {
	sock = strings.TrimPrefix(sock, "tcp:")

	dialFunc := func() (net.Conn, error) {
		return net.DialTimeout("tcp", sock, timeout)
	}

	timeoutErr := grpcStatus.Errorf(codes.DeadlineExceeded, "timed out connecting to tcp socket %s", sock)
	return commonDialer(timeout, dialFunc, timeoutErr)
}
