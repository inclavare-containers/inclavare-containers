// The codebase is inherited from runc with the modifications.

package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"

	"github.com/inclavare-containers/rune/libenclave"
	"github.com/opencontainers/runc/libcontainer/logs"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func parseLogLevel(lvl string) (logrus.Level, error) {
	if lvl == "off" {
		return logrus.ParseLevel("panic")
	}

	return logrus.ParseLevel(lvl)
}

func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()

		level := os.Getenv("_LIBCONTAINER_LOGLEVEL")
		logLevel, err := logrus.ParseLevel(level)
		if err != nil {
			panic(fmt.Sprintf("libenclave: failed to parse log level: %q: %v", level, err))
		}

		logPipeFdStr := os.Getenv("_LIBCONTAINER_LOGPIPE")
		logPipeFd, err := strconv.Atoi(logPipeFdStr)
		if err != nil {
			panic(fmt.Sprintf("libenclave: failed to convert environment variable _LIBCONTAINER_LOGPIPE=%s to int: %s", logPipeFdStr, err))
		}
		err = logs.ConfigureLogging(logs.Config{
			LogPipeFd: logPipeFd,
			LogFormat: "json",
			LogLevel:  logLevel,
		})
		if err != nil {
			panic(fmt.Sprintf("libenclave: failed to configure logging: %v", err))
		}
		logrus.Debug("child process in init()")
	}
}

var initCommand = cli.Command{
	Name:  "init",
	Usage: `initialize the namespaces and launch the process (do not call it outside of rune)`,
	Action: func(context *cli.Context) error {
		factory, _ := libenclave.New("", nil, false)
		if err := factory.StartInitialization(); err != nil {
			// as the error is sent back to the parent there is no need to log
			// or write it to stderr because the parent process will handle this
			// However, locating the log file is painful especially using docker
			// or any high level container runtime, so the error is still printed
			// to stderr if --debug is specified.
			if context.GlobalBool("debug") {
				fmt.Fprint(os.Stderr, err)
			}
			os.Exit(1)
		}
		panic("libenclave: container init failed to exec")
	},
}
