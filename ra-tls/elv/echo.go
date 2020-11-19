package main

/*
#cgo CFLAGS: -I../build/include -I/opt/intel/sgxsdk/include -I../sgx-ra-tls
#cgo LDFLAGS: -L../build/lib -l:libra-challenger.a -l:libwolfssl.a -lm

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

		//conn, err := net.Dial("unix", addr)
		conn, err := net.Dial("tcp", "localhost:3443")
		if err != nil {
			return err
		}
		defer conn.Close()

		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			return fmt.Errorf("casting to UnixConn failed")
		}

		sockfd, err := tcpConn.File()
		if err != nil {
			return err
		}

		C.ra_tls_echo(C.int(sockfd.Fd()))

		return nil
	},
}
