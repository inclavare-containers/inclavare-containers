package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/opencontainers/runc/libcontainer/logs"
	"github.com/opencontainers/runc/libenclave"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "enclave" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()

		level := os.Getenv("_LIBENCLAVE_LOGLEVEL")
		logLevel, err := logs.ParseLogLevel(level)
		if err != nil {
			panic(fmt.Sprintf("runelet: failed to parse log level: %q: %v", level,
				err))
		}

		err = logs.ConfigureLogging(logs.Config{
			LogPipeFd: os.Getenv("_LIBENCLAVE_LOGPIPE"),
			LogFormat: "json",
			LogLevel:  logLevel,
		})
		if err != nil {
			panic(fmt.Sprintf("runelet: failed to configure logging: %v", err))
		}
		logrus.Debug("runelet process started")
	}
}

var enclaveCommand = cli.Command{
	Name:  "enclave",
	Usage: `initialize the enclave runtime (do not call it outside of rune)`,
	Action: func(context *cli.Context) error {
		exitCode, err := libenclave.StartInitialization()
		if err != nil {
			logrus.Fatal(err)
		}
		os.Exit(int(exitCode))
		panic("runelet process failed to exit")
	},
}
