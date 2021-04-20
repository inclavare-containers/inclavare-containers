package main

import (
	"fmt"
	"github.com/inclavare-containers/shelter/remoteattestation"
	"github.com/urfave/cli"
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
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "ip",
			Usage: "tcp socket ip to connect inclavared",
		},
		cli.StringFlag{
			Name:  "port",
			Usage: "tcp socket port to connect inclavared",
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
		cli.StringFlag{
			Name:  "mutual",
			Usage: "set the attestation type is mutual or not",
		},
	},
	SkipArgReorder: true,
	Action: func(cliContext *cli.Context) error {
		tcpIp := cliContext.String("ip")
		tcpPort := cliContext.String("port")
		logLevelInit := cliContext.String("log-level")
		attester := cliContext.String("attester")
		verifier := cliContext.String("verifier")
		tls := cliContext.String("tls")
		crypto := cliContext.String("crypto")
		var mutual bool = false
		mutual = (bool)(cliContext.Bool("mutual"))
		//attestation based on enclave-tls in tcp socket
		ret := remoteattestation.EnclaveTlsSetupTcpSock(tcpIp, tcpPort, logLevelInit, attester, verifier, tls, crypto, mutual)
		//attestation based on enclave-tls in unix socket, keep it for test
		//ret := remoteattestation.EnclaveTlsSetupUnixSock(socketAddr, logLevelInit, attester, verifier, tls, crypto, mutual)
		if ret != nil {
			return fmt.Errorf("RemotTlsSetup failed with err: %s \n", ret)
		}

		fmt.Printf("remote attestation is successful.\n")
		return nil

	},
}
