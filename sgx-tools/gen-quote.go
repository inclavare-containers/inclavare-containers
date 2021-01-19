package main // import "github.com/inclavare-containers/sgx-tools"

import (
	"fmt"
	_ "github.com/inclavare-containers/rune/libenclave/attestation"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"io/ioutil"
	"strings"
)

var generateQuoteCommand = cli.Command{
	Name:  "gen-quote",
	Usage: "retrieve a quote from aesmd",
	ArgsUsage: `[command options]

EXAMPLE:
For example, generate the quote file according to the given local report file:

	# sgx-tools gen-quote --report foo.rep --spid ${SPID}`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "quoteType",
			Usage: "specify the SGX quote type such as epid for unlinkable, epid for linkable and ecdsa",
		},
		cli.StringFlag{
			Name:  "report",
			Usage: "path to the input report file containing REPORT",
		},
		cli.StringFlag{
			Name:  "spid",
			Usage: "spid",
		},
		cli.StringFlag{
			Name:  "quote",
			Usage: "path to the output quote file containing QUOTE",
		},
	},
	Action: func(context *cli.Context) error {
		reportPath := context.String("report")
		if reportPath == "" {
			return fmt.Errorf("report argument cannot be empty")
		}

		if context.GlobalBool("verbose") {
			logrus.SetLevel(logrus.DebugLevel)
		}

		quotePath := context.String("quote")
		if quotePath == "" {
			quotePath = "quote.bin"
		}

		report, err := readAndCheckFile(reportPath, intelsgx.ReportLength)
		if err != nil {
			return err
		}

		quoteType := context.String("quoteType")
		if !strings.EqualFold(quoteType, quoteTypeEcdsa) && !strings.EqualFold(quoteType, quoteTypeEpidUnlinkable) && !strings.EqualFold(quoteType, quoteTypeEpidLinkable) {
			return fmt.Errorf("Unsupport quote type: %v", quoteType)
		}

		quote, err := GetQuoteEx(quoteType, report, context.String("spid"))
		if err != nil {
			return err
		}

		if err := ioutil.WriteFile(quotePath, quote, 0664); err != nil {
			return err
		}

		logrus.Infof("target enclave's quote file %s saved", quotePath)

		return nil
	},
	SkipArgReorder: true,
}
