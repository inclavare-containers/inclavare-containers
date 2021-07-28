package main

import (
	"flag"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"k8s.io/klog/v2"

	"github.com/inclavare-containers/shim/cmd/signature-server/app"
)

var onlyOneSignalHandler = make(chan struct{})
var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

func setupSignalHandler() <-chan struct{} {
	close(onlyOneSignalHandler) // panics when called twice

	stop := make(chan struct{})
	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		<-c
		close(stop)
		<-c
		os.Exit(1) // second signal. Exit directly.
	}()

	return stop
}

func main() {
	//logs.InitLogs()
	//defer logs.FlushLogs()
	if len(os.Getenv("GOMAXPROCS")) == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	stopCh := setupSignalHandler()

	cmd := app.NewSignatureServer(stopCh)
	cmd.Flags().AddGoFlagSet(flag.CommandLine)

	if err := cmd.Execute(); err != nil {
		klog.Fatal(err)
	}

	flag.CommandLine.Parse([]string{})

	if err := cmd.Execute(); err != nil {
		klog.Fatal(err)
	}
}
