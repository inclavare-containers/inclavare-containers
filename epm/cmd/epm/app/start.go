package app

import (
	"github.com/alibaba/inclavare-containers/epm/cmd/epm/app/options"
	"github.com/spf13/cobra"
)

// NewEnclavePoolManagerServer creat and start the enclave pool manager server
func NewEnclavePoolManagerServer() *cobra.Command {
	opts := &options.Options{}
	cmd := &cobra.Command{
		Short: "Launch signature server",
		Long:  "Launch signature server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer(opts)
		},
	}
	flags := cmd.Flags()
	opts.AddFlags(flags)
	return cmd
}
