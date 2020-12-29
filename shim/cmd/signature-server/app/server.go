package app

import (
	"github.com/golang/glog"

	"github.com/inclavare-containers/shim/cmd/signature-server/app/options"
	"github.com/inclavare-containers/shim/runtime/signature/server"
	"github.com/inclavare-containers/shim/runtime/signature/server/conf"
)

func runServer(opts *options.SignatureServerOptions, stopCh <-chan struct{}) error {
	var err error
	var cnf conf.Config

	if err = opts.ApplyTo(&cnf); err != nil {
		return err
	}

	svr, err := server.NewServer(&cnf)
	if err != nil {
		glog.Fatalf("failed to init toolkit server, err:%s", err.Error())
		return err
	}
	svr.Start(stopCh)
	return nil
}
