package main // import "github.com/inclavare-containers/inclavared"

// The LDFLAGS defined by cgo doesn't support runtpath enabled by --enable-new-dtags, so rpath is used by default

/*
#cgo CFLAGS: -I../../src/include
#cgo LDFLAGS: -L../../src -Wl,-rpath,'/opt/enclave-tls/lib' -lenclave_tls -lsgx_urts -lm

#include <enclave-tls/api.h>

extern int ra_tls_server_startup(int, enclave_tls_log_level_t, char *, char *, char *, char *);
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
			Name:  "attester",
			Usage: "set he type of quote attester",
		},
		cli.StringFlag{
			Name:  "verifier",
			Usage: "set the type of quote verifier",
		},
		cli.StringFlag{
			Name:  "tls",
			Usage: "set the type of tls wrapper",
		},
		cli.StringFlag{
			Name:  "crypto",
			Usage: "set the type of crypto wrapper",
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

		attester := cliContext.String("attester")
		verifier := cliContext.String("verifier")
		tls := cliContext.String("tls")
		crypto := cliContext.String("crypto")

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

		C.ra_tls_server_startup(C.int(connFile.Fd()), C.enclave_tls_log_level_t(logLevel), C.CString(attester), C.CString(verifier), C.CString(tls), C.CString(crypto))

		return nil
	},
}
