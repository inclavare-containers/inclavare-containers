package main

import (
	"fmt"
	"github.com/inclavare-containers/shelter/utils"
	"github.com/inclavare-containers/shelter/verification"
	"github.com/urfave/cli"
	"unsafe"
	"path/filepath"
)

const (
	defaultSrcUrl      = "https://github.com/alibaba/inclavare-containers/"
	defaultSrcBranch   = "master"
	defaultSrcCommitId = ""
	defaultLocalPath   = "/tmp/skeleton/"

	defaultScrPathPrefix = "/tmp/skeleton/"
	defaultScrPathSuffix = "rune/libenclave/internal/runtime/pal/skeleton/"

	defaultEncss     = "/tmp/skeleton/rune/libenclave/internal/runtime/pal/skeleton/encl.ss"
	targetEncbinPath = defaultScrPathPrefix + defaultScrPathSuffix
	targetEncbin     = "encl.bin"
	targetEncss      = "encl.ss"
)

var (
        GlobalUrl string = ""
        GlobalBranch string = ""
)

var mrverifyCommand = cli.Command{
	Name:  "mrverify",
	Usage: "download target source code to rebuild and caculate launch measurement based on software algorithm and then compare with launch measurement in sigsturct file",
	ArgsUsage: `[command options]

EXAMPLE:
       # shelter mrenclave`,
	/*	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "addr",
			Usage: "ra-tls server address",
		},
		cli.StringFlag{
			Name:  "port",
			Usage: "ra-tls server port",
		},
	},*/

	SkipArgReorder: true,

	Action: func(cliContext *cli.Context) error {

		var mrEnclave [32]byte
		var maxMapSize uint64

		if GlobalUrl == "" {
			GlobalUrl = defaultSrcUrl
		}

		if GlobalBranch == "" {
			GlobalBranch = defaultSrcBranch
		}

		fmt.Printf("prepare download code and build target bin file.\n")
		if ret := utils.GetSrcCode(GlobalUrl, GlobalBranch, "", defaultLocalPath); !ret {
			return fmt.Errorf("get src code failed.\n")
		}

		//srcPath := string(defaultScrPathPrefix + defaultScrPathSuffix)
		srcPath := filepath.Join(defaultScrPathPrefix, defaultScrPathSuffix)
		if !utils.BuildTargetSrc(srcPath) {
			return fmt.Errorf("build src code failed.\n")
		}

		//targetBinPath := targetEncbinPath + targetEncbin
		targetBinPath := filepath.Join(targetEncbinPath, targetEncbin)
		maxMapSize = 0

		if !verification.Measure_Encl(targetBinPath, unsafe.Pointer(&mrEnclave[0]), maxMapSize) {
			return fmt.Errorf("measure mrEnclave failed.\n")
		}

		if !verification.Mrenclave_VerifybySigstruct(defaultEncss, unsafe.Pointer(&mrEnclave[0])) {
			return fmt.Errorf("mismatch with sigstruct mrEnclave value.\n")
		}
		fmt.Printf("new mrEnclave match the vallue in sigstruct file successfully.\n")
		return nil
	},
}
