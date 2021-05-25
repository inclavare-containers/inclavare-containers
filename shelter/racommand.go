package main

import (
	"fmt"
	"github.com/inclavare-containers/shelter/remoteattestation"
	"github.com/inclavare-containers/shelter/utils"
	"github.com/urfave/cli"
	"strings"
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
			Name:  "addr",
			Usage: "specify tcp or unix socket address, e.g, '--addr=tcp://ip:port or --addr=unix://path'",
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
		cli.BoolFlag{
			Name:  "mutual",
			Usage: "set the attestation type is mutual or not",
		},
	},
	SkipArgReorder: true,
	Action: func(cliContext *cli.Context) error {
		sockAddr := cliContext.String("addr")
		logLevelInit := cliContext.String("log-level")
		attester := cliContext.String("attester")
		verifier := cliContext.String("verifier")
		tls := cliContext.String("tls")
		crypto := cliContext.String("crypto")
		var mutual bool = false
		if cliContext.Bool("mutual") {
			mutual = true
		}
		var ret error = nil
		var tcpIp string = ""
		var tcpPort string = ""
		var unixSock string = ""
		var manageCmd string = ""
		manageCmd = utils.ManageCmd1

		if sockAddr != "" {
			s1 := strings.Contains(sockAddr, "tcp")
			s2 := strings.Contains(sockAddr, "unix")
			if !s1 && !s2 {
				return fmt.Errorf("warning: specify tcp or unix socket address with error format.\n")
			}
			if s1 {
				ss := strings.Split(sockAddr, ":")
				if len(ss) < 3 {
					return fmt.Errorf("warning: specify tcp socket address with error format.\n")
				}
				tcpPort = ss[2]
				sss := strings.TrimLeft(ss[1], "//")
				tcpIp = sss
				if tcpIp != "" {
					n := strings.Count(tcpIp, ".")
					if n != 3 {
						return fmt.Errorf("warning: specify tcp socket ip address with error format.\n")
					}
				}
			} else if s2 {
				ss := strings.Split(sockAddr, ":")
				if len(ss) < 2 {
					return fmt.Errorf("warning: specify unix socket address with error format.\n")
				}
				sss := strings.TrimPrefix(ss[1], "//")
				unixSock = sss
			}
		}
		//attestation based on enclave-tls in tcp socket
		if tcpIp != "" || tcpPort != "" {
			ret = remoteattestation.EnclaveTlsSetupTcpSock(tcpIp, tcpPort, logLevelInit, attester, verifier, tls, crypto, mutual, manageCmd)
		} else if unixSock != "" {
			ret = remoteattestation.EnclaveTlsSetupUnixSock(unixSock, logLevelInit, attester, verifier, tls, crypto, mutual, manageCmd)
		} else if unixSock == "" && tcpIp == "" && tcpPort == "" {
			//if no any socket is specified, try to connect use default tcp port to connect firstly;
			ret = remoteattestation.EnclaveTlsSetupTcpSock(tcpIp, tcpPort, logLevelInit, attester, verifier, tls, crypto, mutual, manageCmd)
			retstr := fmt.Sprintf("%s", ret)
			if strings.Contains(retstr, "connection") {
				//if tcp socket connection is refused, try to connect use default unix socket to connect as backup;
				fmt.Printf("Try to connect default tcp socket failed then retry with default unix socket.\n")
				ret = remoteattestation.EnclaveTlsSetupUnixSock(unixSock, logLevelInit, attester, verifier, tls, crypto, mutual, manageCmd)
			}
		}
		if ret != nil {
			return fmt.Errorf("Remote attestation failed with err: %s \n", ret)
		}

		fmt.Printf("Remote attestation is successful.\n")
		return nil

	},
}
