package main // import "github.com/inclavare-containers/sgx-tools"

import (
	"encoding/binary"
	"fmt"
	"github.com/go-restruct/restruct"
	"github.com/inclavare-containers/rune/libenclave/attestation"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"log"
	"strings"
)

var verifyQuoteCommand = cli.Command{
	Name:  "verify-quote",
	Usage: "verify quote with the help of IAS",
	ArgsUsage: `[command options]
EXAMPLE:
For example, get remote attestation report from IAS according to quote file:
	# sgx-tools verify-quote --quote-type=${SGX_QUOTE_TYPE} --quote foo.quote --spid ${SPID} --subscription-key ${SUBSCRIPTION_KEY}`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "quote-type",
			Usage: "specify the SGX quote type such as epidUnlinkable, epidLinkable and ecdsa",
		},
		cli.StringFlag{
			Name:  "quote",
			Usage: "path to the input quote file containing QUOTE",
		},
		cli.StringFlag{
			Name:  "spid",
			Usage: "spid",
		},
		cli.StringFlag{
			Name:  "subscription-key, -key",
			Usage: "specify the subscription key",
		},
	},
	Action: func(context *cli.Context) error {
		quoteType := context.String("quote-type")
		if !strings.EqualFold(quoteType, intelsgx.QuoteTypeEcdsa) && !strings.EqualFold(quoteType, intelsgx.QuoteTypeEpidUnlinkable) && !strings.EqualFold(quoteType, intelsgx.QuoteTypeEpidLinkable) {
			return fmt.Errorf("Unsupport quote type: %v", quoteType)
		}

		quotePath := context.String("quote")
		if quotePath == "" {
			return fmt.Errorf("quote argument cannot be empty")
		}

		if context.GlobalBool("verbose") {
			logrus.SetLevel(logrus.DebugLevel)
		}

		quote, err := readFile(quotePath)
		if err != nil {
			return err
		}

		var attestationType string
		var p map[string]string

		if strings.EqualFold(quoteType, intelsgx.QuoteTypeEpidUnlinkable) || strings.EqualFold(quoteType, intelsgx.QuoteTypeEpidLinkable) {
			if len(quote) > intelsgx.SgxEpidMaxQuoteLength {
				return fmt.Errorf("quote file %s not match epid quote", quotePath)
			}

			spid := context.String("spid")
			if spid == "" {
				return fmt.Errorf("spid argument cannot be empty")
			}
			if len(spid) != intelsgx.SpidLength*2 {
				return fmt.Errorf("Spid must be %d-character long", intelsgx.SpidLength*2)
			}

			subscriptionKey := context.String("subscription-key")
			if subscriptionKey == "" {
				return fmt.Errorf("subscription-key argument cannot be empty")
			}
			if len(subscriptionKey) != intelsgx.AttestationSubscriptionKeyLength*2 {
				return fmt.Errorf("Subscription-key must be %d-character long", intelsgx.AttestationSubscriptionKeyLength*2)
			}

			q := &intelsgx.Quote{}
			if err := restruct.Unpack(quote, binary.LittleEndian, &q); err != nil {
				return err
			}

			product, err := IsProductEnclave(q.ReportBody)
			if err != nil {
				return err
			}

			// get IAS remote attestation report
			p = parseAttestParameters(spid, subscriptionKey, product)
			attestationType = intelsgx.AttestationEpid
		} else {
			if len(quote) < intelsgx.SgxEcdsaMinQuoteLength {
				return fmt.Errorf("quote file %s not match ecdsa quote", quotePath)
			}

			attestationType = intelsgx.AttestationEcdsa
		}

		challenger, err := attestation.NewChallenger(attestationType, p)
		if err != nil {
			log.Fatal(err)
			return err
		}

		if err = challenger.Check(quote); err != nil {
			log.Fatal(err)
			return err
		}

		if _, _, err = challenger.Verify(quote); err != nil {
			log.Fatal(err)
			return err
		}

		if attestationType == intelsgx.AttestationEpid {
			status, specificStatus, iasReport, err := challenger.GetReport(quote, 0)
			if err != nil {
				return fmt.Errorf("%s", err)
			}

			challenger.ShowReportStatus(status, specificStatus)

			logrus.Infof("iasReport = %v", iasReport)
		}

		return nil
	},
	SkipArgReorder: true,
}

func parseAttestParameters(spid string, subscriptionKey string, product bool) map[string]string {
	p := make(map[string]string)

	p["spid"] = spid
	p["subscription-key"] = subscriptionKey
	p["service-class"] = "dev"
	if product {
		p["service-class"] = "product"
	}

	return p
}
