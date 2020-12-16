package app

import (
	"github.com/inclavare-containers/epm/cmd/epm/app/options"
	"github.com/spf13/cobra"
)

// NewEnclavePoolManagerServer creat and start the enclave pool manager server
func NewEnclavePoolManagerServer(stopCh <-chan struct{}) *cobra.Command {
	opts := &options.Options{}
	cmd := &cobra.Command{
		Short: "Launch epm server",
		Long:  "Launch epm server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer(opts, stopCh)
		},
	}
	flags := cmd.Flags()
	opts.AddFlags(flags)
	return cmd
}
