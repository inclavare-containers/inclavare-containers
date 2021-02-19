// +build lareport

package main

/*
#cgo CFLAGS: -I../build/include -I/opt/intel/sgxsdk/include -I../sgx-ra-tls -I../wolfssl/
#cgo CFLAGS: -DLA_REPORT=1
#cgo LDFLAGS: -L../build/lib -l:libra-challenger.a -l:libwolfssl.a -lsgx_urts -lm

#include <stdio.h>
#include <string.h>
#include "sgx_urts.h"

sgx_enclave_id_t g_eid = 0;
static sgx_enclave_id_t load_enclave(void)
{
        sgx_launch_token_t t;
        memset(t, 0, sizeof(t));

        sgx_enclave_id_t id;
        int updated = 0;
        int ret = sgx_create_enclave("Wolfssl_Enclave.signed.so", 1, &t, &updated, &id, NULL);
        if (ret != SGX_SUCCESS) {
                fprintf(stderr, "Failed to create Enclave: error %d\n", ret);
                return -1;
        }

        return id;
}

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
		C.g_eid = C.load_enclave()

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
