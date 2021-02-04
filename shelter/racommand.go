package main

import (
	"fmt"
	"github.com/inclavare-containers/shelter/remoteattestation"
	"github.com/urfave/cli"
	"unsafe"
)

var (
	remoteMrenclave [32]byte
	remoteMrsigner  [32]byte
)

var sgxraCommand = cli.Command{
	Name:  "remoteattestation",
	Usage: "attest IAS report obtained by inclavared and setup TLS security channel with inclavared",
	ArgsUsage: `[command options]

EXAMPLE:
       # shelter mrenclave`,
	/*	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "none",
			Usage: "none",
		},
		cli.StringFlag{
			Name:  "none",
			Usage: "none",
		},
	},*/

	SkipArgReorder: true,

	Action: func(cliContext *cli.Context) error {

		var socketAddr string
		socketAddr = cliContext.String("addr")
		//connect to inclavared by TCP socket
		//ret := remoteattestation.RemoteTlsSetupTCP(socketAddr, (unsafe.Pointer)(&remoteMrenclave[0]), (unsafe.Pointer)(&remoteMrsigner[0]))
		//connect to ra-tls-server by unix socket
		ret := remoteattestation.RemoteTlsSetupSock(socketAddr, (unsafe.Pointer)(&remoteMrenclave[0]), (unsafe.Pointer)(&remoteMrsigner[0]))
		if ret != nil {
			return fmt.Errorf("RemotTlsSetup failed with err: %s \n", ret)
		}

		fmt.Printf("remote attestation is successful.\n")
		return nil

	},
}
