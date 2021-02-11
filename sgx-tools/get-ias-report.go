package main // import "github.com/inclavare-containers/sgx-tools"

import (
	"encoding/binary"
	"fmt"
	"github.com/go-restruct/restruct"
	"github.com/inclavare-containers/rune/libenclave/attestation"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"io"
	"log"
	"os"
)

var getIasReportCommand = cli.Command{
	Name:  "get-ias-report",
	Usage: "get remote attestation report from IAS",
	ArgsUsage: `[command options]

EXAMPLE:
For example, get remote attestation report from IAS according to quote file:

	# sgx-tools get-ias-report --quote foo.quote --spid ${SPID} --subscription-key ${SUBSCRIPTION_KEY}`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "quote",
			Usage: "path to the input quote file containing QUOTE",
		},
		cli.StringFlag{
			Name:  "ias-report",
			Usage: "path to the output IAS report file containing IAS report",
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
		quotePath := context.String("quote")
		if quotePath == "" {
			return fmt.Errorf("quote argument cannot be empty")
		}

		iasReportPath := context.String("ias-report")
		if iasReportPath == "" {
			iasReportPath = "ias-report.bin"
		}

		spid := context.String("spid")
		if spid == "" {
			return fmt.Errorf("spid argument cannot be empty")
		}

		subscriptionKey := context.String("subscription-key")
		if subscriptionKey == "" {
			return fmt.Errorf("subscription-key argument cannot be empty")
		}

		if context.GlobalBool("verbose") {
			logrus.SetLevel(logrus.DebugLevel)
		}

		rf, err := os.Open(quotePath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("quote file %s not found", quotePath)
			}
			return err
		}
		defer rf.Close()

		var rfi os.FileInfo
		rfi, err = rf.Stat()
		if err != nil {
			return err
		}

		if rfi.Size() > intelsgx.SgxMaxQuoteLength {
			return fmt.Errorf("quote file %s not match Quote", quotePath)
		}

		quote := make([]byte, rfi.Size())
		if _, err = io.ReadFull(rf, quote); err != nil {
			return fmt.Errorf("quote file %s read failed", quotePath)
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
		p := parseAttestParameters(spid, subscriptionKey, product)
		challenger, err := attestation.NewChallenger("sgx-epid", p)
		if err != nil {
			log.Fatal(err)
			return err
		}

		if err = challenger.Check(quote); err != nil {
			log.Fatal(err)
			return err
		}

		status, specificStatus, iasReport, err := challenger.GetReport(quote, 0)
		if err != nil {
			return fmt.Errorf("%s", err)
		}

		challenger.ShowReportStatus(status, specificStatus)

		logrus.Infof("iasReport = %v", iasReport)

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
