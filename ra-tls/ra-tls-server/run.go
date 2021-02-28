package main

import (
	"fmt"
	"github.com/urfave/cli"
	"net"
	"syscall"
)

const (
	defaultAddress = "/run/rune/ra-tls.sock"
)

var runCommand = cli.Command{
	Name:  "run",
	Usage: "run the inclavared",
	ArgsUsage: `[command options]

EXAMPLE:

       # shelterd-shim-agent run &`,
	Flags: []cli.Flag{
		/*
			cli.IntFlag{
				Name:        "port",
				Value:       listeningPort,
				Usage:       "listening port for receiving external requests",
				Destination: &listeningPort,
			},
		*/
		cli.StringFlag{
			Name:  "addr",
			Usage: "the timeout in second for re-establishing the connection to inclavared",
		},
	},
	SkipArgReorder: true,
	Action: func(cliContext *cli.Context) error {
		addr := cliContext.String("addr")
		if addr == "" {
			addr = defaultAddress
		}

		syscall.Unlink(addr)

		ln, err := net.Listen("unix", addr)
		if err != nil {
			return err
		}
		defer ln.Close()

		unixListener, ok := ln.(*net.UnixListener)
		if !ok {
			return fmt.Errorf("casting to UnixListener failed")
		}

		unixListener.SetUnlinkOnClose(false)
		defer unixListener.SetUnlinkOnClose(true)

		c, err := unixListener.Accept()
		if err != nil {
			return err
		}
		defer c.Close()

		conn, ok := c.(*net.UnixConn)
		if !ok {
			return fmt.Errorf("casting to UnixConn failed")
		}

		connFile, err := conn.File()
		if err != nil {
			return err
		}
		defer connFile.Close()

		ratlsServerStartup(connFile.Fd())

		return nil
	},
}
