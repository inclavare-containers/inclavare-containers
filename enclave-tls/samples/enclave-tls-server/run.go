package main // import "github.com/inclavare-containers/inclavared"

// The LDFLAGS defined by cgo doesn't support runtpath enabled by --enable-new-dtags, so rpath is used by default

/*
#cgo CFLAGS: -I../../src/include
#cgo LDFLAGS: -L../../src -Wl,-rpath,'/opt/enclave-tls/lib' -lenclave_tls -lm

#include <enclave-tls/api.h>

extern int ra_tls_server_startup(int, enclave_tls_log_level_t, char*, char*, char*);
*/
import "C"
import (
	"fmt"
	"github.com/urfave/cli"
	"net"
	"strings"
	"syscall"
)

const (
	defaultAddress = "/run/enclave-tls/tls.sock"
)

var runCommand = cli.Command{
	Name:  "run",
	Usage: "run the ra-tls-server",
	ArgsUsage: `[command options]

EXAMPLE:

       # ra-tls-server run &`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "addr",
			Usage: "the server address",
		},
		cli.StringFlag{
			Name:  "log-level",
			Usage: "set the level of log output",
		},
		cli.StringFlag{
			Name:  "attester-type",
			Usage: "set he type of quote attester instance",
		},
		cli.StringFlag{
			Name:  "verifier-type",
			Usage: "set the type of quote verifier instance",
		},
		cli.StringFlag{
			Name:  "tls-type",
			Usage: "set the type of TLS Lib",
		},
	},
	SkipArgReorder: true,
	Action: func(cliContext *cli.Context) error {
		addr := cliContext.String("addr")
		if addr == "" {
			addr = defaultAddress
		}

		logLevel := C.ENCLAVE_TLS_LOG_LEVEL_DEBUG
		if strings.EqualFold(cliContext.String("log-level"), "debug") {
			logLevel = C.ENCLAVE_TLS_LOG_LEVEL_DEBUG
		} else if strings.EqualFold(cliContext.String("log-level"), "info") {
			logLevel = C.ENCLAVE_TLS_LOG_LEVEL_INFO
		}

		attesterType := cliContext.String("attester-type")
		verifierType := cliContext.String("verifier-type")
		tlsType := cliContext.String("tls-type")

		syscall.Unlink(addr)

		ln, err := net.Listen("unix", addr)
		if err != nil {
			return err
		}
		defer ln.Close()

		unixListener, ok := ln.(*net.UnixListener)
		if !ok {
			return fmt.Errorf("casting to UnixListener failed")
		}

		unixListener.SetUnlinkOnClose(false)
		defer unixListener.SetUnlinkOnClose(true)

		c, err := unixListener.Accept()
		if err != nil {
			return err
		}
		defer c.Close()

		conn, ok := c.(*net.UnixConn)
		if !ok {
			return fmt.Errorf("casting to UnixConn failed")
		}

		connFile, err := conn.File()
		if err != nil {
			return err
		}
		defer connFile.Close()

		C.ra_tls_server_startup(C.int(connFile.Fd()), C.enclave_tls_log_level_t(logLevel), C.CString(attesterType), C.CString(verifierType), C.CString(tlsType))

		return nil
	},
}
