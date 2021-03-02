package main

/*
#cgo CFLAGS: -I../../src/include
#cgo LDFLAGS: -L../../src -lenclave_tls -lm

#include <enclave-tls/api.h>

extern int ra_tls_echo(int, enclave_tls_log_level_t, char*, char*, char*);
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
			Name:  "attester-type",
			Usage: "set the type of quote attester instance",
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

		C.ra_tls_echo(C.int(sockfd.Fd()), C.enclave_tls_log_level_t(logLevel), C.CString(attesterType), C.CString(verifierType), C.CString(tlsType))
		return nil
	},
}
