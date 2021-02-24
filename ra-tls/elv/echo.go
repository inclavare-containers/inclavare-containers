package main

/*
#cgo CFLAGS: -I../build/include -I/opt/intel/sgxsdk/include -I../sgx-ra-tls -I../wolfssl/
#cgo LDFLAGS: -L../build/lib -l:libra-challenger.a -l:libwolfssl.a -lm
#ifdef RATLS_ECDSA
#cgo LDFLAGS:  -lsgx_dcap_quoteverify -lsgx_urts -lpthread -ldl -lsgx_dcap_ql
#endif

extern int ra_tls_echo(int sockfd);
*/
import "C"
import (
	"fmt"
	"github.com/urfave/cli"
	"net"
)

const (
	defaultAddress = "/run/rune/ra-tls.sock"
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
	},
	SkipArgReorder: true,
	Action: func(cliContext *cli.Context) error {
		addr := cliContext.String("addr")
		if addr == "" {
			addr = defaultAddress
		}

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

		C.ra_tls_echo(C.int(sockfd.Fd()))

		return nil
	},
}
