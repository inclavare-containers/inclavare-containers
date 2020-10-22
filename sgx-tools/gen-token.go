package main // import "github.com/inclavare-containers/sgx-tools"

import (
	"fmt"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var generateTokenCommand = cli.Command{
	Name:  "gen-token",
	Usage: "retrieve a token from aesmd",
	ArgsUsage: `[command options]

EXAMPLE:
For example, generate the token file according to the given signature file:

	# sgx-tools gen-token --signature foo.sig`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "signature",
			Usage: "path to the input signature file (.sig) containing SIGSTRUCT",
		},
		cli.StringFlag{
			Name:  "token",
			Usage: "path to the output token file (.token) containing EINITTOKEN",
		},
	},
	Action: func(context *cli.Context) error {

		if intelsgx.IsSGXLaunchControlSupported() {
			return fmt.Errorf("gen-token command is unable to run without SGX launch control feature")
		}

		sigPath := context.String("signature")
		if sigPath == "" {
			return fmt.Errorf("signature argument cannot be empty")
		}

		sf, err := os.Open(sigPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("signature file %s not found", sigPath)
			}
			return err
		}
		defer sf.Close()

		var sfi os.FileInfo
		sfi, err = sf.Stat()
		if err != nil {
			return err
		}

		if sfi.Size() != intelsgx.SigStructLength {
			return fmt.Errorf("signature file %s not match SIGSTRUCT", sigPath)
		}

		if context.GlobalBool("verbose") {
			logrus.SetLevel(logrus.DebugLevel)
		}

		buf := make([]byte, intelsgx.SigStructLength)
		if _, err = io.ReadFull(sf, buf); err != nil {
			return fmt.Errorf("signature file %s read failed", sigPath)
		}

		tok, err := intelsgx.GetLaunchToken(buf)
		if err != nil {
			logrus.Print(err)
			return err
		}

		tokenPath := context.String("token")
		if tokenPath == "" {
			tokenPath = filepath.Dir(sigPath)
			if tokenPath == "." {
				tokenPath = ""
			} else if strings.HasPrefix(tokenPath, "../") {
				if tokenPath, err = filepath.Abs(tokenPath); err != nil {
					return err
				}
				tokenPath += "/"
			} else {
				tokenPath += "/"
			}

			baseName := filepath.Base(sigPath)
			if strings.HasSuffix(baseName, ".sig") {
				tokenPath += baseName[:strings.LastIndex(baseName, ".sig")]
			}
			tokenPath += ".token"
		}

		if err := ioutil.WriteFile(tokenPath, tok, sfi.Mode().Perm()); err != nil {
			return err
		}

		if context.GlobalBool("verbose") {
			fmt.Printf("token file %s saved\n", tokenPath)
		}

		return nil
	},
	SkipArgReorder: true,
}
