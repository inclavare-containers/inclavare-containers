package main // import "github.com/inclavare-containers/runectl"

import (
	"fmt"
	"github.com/opencontainers/runc/libenclave/intelsgx"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"io"
	"io/ioutil"
	"os"
)

var generateQuoteCommand = cli.Command{
	Name:  "gen-quote",
	Usage: "retrieve a quote from aesmd",
	ArgsUsage: `[command options]

EXAMPLE:
For example, generate the quote file according to the given local report file:

	# runectl gen-quote --report foo.rep`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "report",
			Usage: "path to the input report file containing REPORT",
		},
		cli.StringFlag{
			Name:  "quote",
			Usage: "path to the output quote file containing QUOTE",
		},
		cli.StringFlag{
			Name:  "spid",
			Usage: "spid",
		},
		cli.BoolFlag{
			Name:  "linkable",
			Usage: "specify the EPID signatures policy type",
		},
	},
	Action: func(context *cli.Context) error {
		reportPath := context.String("report")
		if reportPath == "" {
			return fmt.Errorf("report argument cannot be empty")
		}

		spid := context.String("spid")
		if spid == "" {
			return fmt.Errorf("spid argument cannot be empty")
		}

		if context.GlobalBool("verbose") {
			logrus.SetLevel(logrus.DebugLevel)
		}

		quotePath := context.String("quote")
		if quotePath == "" {
			quotePath = "quote.bin"
		}

		rf, err := os.Open(reportPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("report file %s not found", reportPath)
			}
			return err
		}
		defer rf.Close()

		var rfi os.FileInfo
		rfi, err = rf.Stat()
		if err != nil {
			return err
		}

		if rfi.Size() != intelsgx.ReportLength {
			return fmt.Errorf("report file %s not match REPORT", reportPath)
		}

		buf := make([]byte, intelsgx.ReportLength)
		if _, err = io.ReadFull(rf, buf); err != nil {
			return fmt.Errorf("report file %s read failed", reportPath)
		}

		linkable := false
		if context.Bool("linkable") {
			linkable = true
		}

		quote, err := intelsgx.GetQuote(buf, spid, linkable)
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
