package main

// The LDFLAGS defined by cgo doesn't support runtpath enabled by --enable-new-dtags, so rpath is used by default

/*
#cgo CFLAGS: -I../../src/include
#cgo LDFLAGS: -L../../build/lib -lenclave_tls -Wl,-rpath,/opt/enclave-tls/lib -lm -lsgx_urts

#include <enclave-tls/api.h>

extern int ra_tls_echo(int, enclave_tls_log_level_t, char *, char *, char *, char *);
*/
import "C"
import (
	"fmt"
	"github.com/urfave/cli"
	"net"
	"strings"
)

const (
	defaultAddress = "/run/enclave-tls/tls.sock"
)

var echoCommand = cli.Command{
	Name:  "echo",
	Usage: "echo the message",
	ArgsUsage: `[command options]

EXAMPLE:

       # shelter attest foo.com`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "addr",
			Usage: "ra-tls server address",
		},
		cli.StringFlag{
			Name:  "port",
			Usage: "ra-tls server port",
		},
		cli.StringFlag{
			Name:  "log-level",
			Usage: "set the level of log output",
		},
		cli.StringFlag{
			Name:  "attester",
			Usage: "set the type of quote attester",
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

		conn, err := net.Dial("unix", addr)
		if err != nil {
			return err
		}
		defer conn.Close()

		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			return fmt.Errorf("casting to UnixConn failed")
		}

		sockfd, err := unixConn.File()
		if err != nil {
			return err
		}

		C.ra_tls_echo(C.int(sockfd.Fd()), C.enclave_tls_log_level_t(logLevel), C.CString(attester), C.CString(verifier), C.CString(tls), C.CString(crypto))

		return nil
	},
}
