package main

import (
	"flag"
	"os"
	"runtime"

	"github.com/alibaba/inclavare-containers/epm/cmd/epm/app"
	"github.com/golang/glog"
)

func main() {
	if len(os.Getenv("GOMAXPROCS")) == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	cmd := app.NewCachePoolManagerServer()
	cmd.Flags().AddGoFlagSet(flag.CommandLine)

	if err := cmd.Execute(); err != nil {
		glog.Fatal(err)
	}

	flag.CommandLine.Parse([]string{})
	if err := cmd.Execute(); err != nil {
		glog.Fatal(err)
	}
}
