package main // import "github.com/inclavare-containers/sgx-tools"

import (
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"io/ioutil"
	"strings"
)

var generateQeTargetInfoCommand = cli.Command{
	Name:  "gen-qe-target-info",
	Usage: "retrieve the target information about Quoting Enclave from aesmd",
	ArgsUsage: `[command options]

EXAMPLE:
For example, save the target information file about Quoting Enclave retrieved from aesmd:

	# sgx-tools gen-qe-target-info --quote-type=${SGX_QUOTE_TYPE} --targetinfo foo`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "quote-type",
			Usage: "specify the SGX quote type such as epidUnlinkable, epidLinkable and ecdsa",
		},
		cli.StringFlag{
			Name:  "targetinfo",
			Usage: "path to the output target information file containing TARGETINFO",
		},
	},
	Action: func(context *cli.Context) error {
		if context.GlobalBool("verbose") {
			logrus.SetLevel(logrus.DebugLevel)
		}

		quoteType := context.String("quote-type")
		if !strings.EqualFold(quoteType, intelsgx.QuoteTypeEcdsa) && !strings.EqualFold(quoteType, intelsgx.QuoteTypeEpidUnlinkable) && !strings.EqualFold(quoteType, intelsgx.QuoteTypeEpidLinkable) {
			return fmt.Errorf("Unsupport quote type: %v", quoteType)
		}

		ti, err := intelsgx.GetQeTargetInfoEx(quoteType)
		if err != nil {
			return err
		}

		tiPath := context.String("targetinfo")
		if tiPath == "" {
			tiPath = "qe_targetinfo.bin"
		}

		if err := ioutil.WriteFile(tiPath, ti, 0664); err != nil {
			return err
		}

		logrus.Infof("quoting enclave's target info file %s saved", tiPath)

		return nil
	},
	SkipArgReorder: true,
}
