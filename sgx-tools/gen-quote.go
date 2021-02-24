package main // import "github.com/inclavare-containers/sgx-tools"

import (
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/attestation"
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

	# sgx-tools gen-quote --quote-type=${SGX_QUOTE_TYPE} --report foo.rep --spid ${SPID}`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "quote-type",
			Usage: "specify the SGX quote type such as epidUnlinkable, epidLinkable and ecdsa",
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

		report, err := readFile(reportPath)
		if err != nil {
			return err
		}
		if len(report) != intelsgx.ReportLength {
			return fmt.Errorf("Report must be %d-character long", intelsgx.ReportLength)
		}

		quoteType := context.String("quote-type")
		if !strings.EqualFold(quoteType, intelsgx.QuoteTypeEcdsa) && !strings.EqualFold(quoteType, intelsgx.QuoteTypeEpidUnlinkable) && !strings.EqualFold(quoteType, intelsgx.QuoteTypeEpidLinkable) {
			return fmt.Errorf("Unsupport quote type: %v", quoteType)
		}

		var attestationType string
		var p map[string]string

		if strings.EqualFold(quoteType, intelsgx.QuoteTypeEpidUnlinkable) || strings.EqualFold(quoteType, intelsgx.QuoteTypeEpidLinkable) {
			spid := context.String("spid")
			if spid == "" {
				return fmt.Errorf("spid can't be empty in both epid for unlinkable and epid for linkable modes")
			}

			if len(spid) != intelsgx.SpidLength*2 {
				return fmt.Errorf("Spid must be %d-character long", intelsgx.SpidLength*2)
			}

			p = parseSgxEpidAttester(quoteType, spid)
			attestationType = intelsgx.AttestationEpid
		} else {
			attestationType = intelsgx.AttestationEcdsa
		}

		attester, err := attestation.NewAttester(attestationType, p)
		if err != nil {
			return err
		}

		quote, err := attester.GetQuote(report)
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
