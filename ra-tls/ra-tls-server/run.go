package main // import "github.com/inclavare-containers/enclaved"

/*
#cgo CFLAGS: -I../build/include -I/opt/intel/sgxsdk/include -I../sgx-ra-tls
#cgo LDFLAGS: -L../build/lib -L/opt/intel/sgxsdk/lib64 -Llib -lra-tls-server -l:libcurl-wolfssl.a -l:libwolfssl.a -lsgx_uae_service -lsgx_urts -lz -lm

#include <stdio.h>
#include <string.h>
#include "sgx_urts.h"

extern int ra_tls_server_startup(sgx_enclave_id_t id, int sockfd);

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

var runCommand = cli.Command{
	Name:  "run",
	Usage: "run the enclaved",
	ArgsUsage: `[command options]

EXAMPLE:

       # shelterd-shim-agent run &`,
	Flags: []cli.Flag{
		/*
			cli.IntFlag{
				Name:        "port",
				Value:       listeningPort,
				Usage:       "listening port for receiving external requests",
				Destination: &listeningPort,
			},
		*/
		cli.StringFlag{
			Name:  "addr",
			Usage: "the timeout in second for re-establishing the connection to enclaved",
		},
	},
	SkipArgReorder: true,
	Action: func(cliContext *cli.Context) error {
		eid := C.load_enclave()

		addr := cliContext.String("addr")
		if addr == "" {
			addr = defaultAddress
		}

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

		C.ra_tls_server_startup(eid, C.int(connFile.Fd()))

		return nil
	},
}
