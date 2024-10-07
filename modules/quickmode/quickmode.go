package quickmode

import (
	"os"
	"runtime"

	"github.com/lkarlslund/adalanche/modules/cli"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/spf13/cobra"
)

var autoquick bool

func init() {
	ada := &cobra.Command{
		Use:  "quick",
		RunE: Execute,
	}
	cli.Root.AddCommand(ada)

	// Offer quick mode for Windows users not using command line arguments
	if runtime.GOOS == "windows" && len(os.Args[1:]) == 0 {
		cli.OverrideArgs = []string{"quick"}
		autoquick = true
	}
}

func Execute(cmd *cobra.Command, args []string) error {
	if autoquick {
		ui.Info().Msg("No arguments provided, activating 'quick' mode: will do automatic collection from Active Directory, and then analyze. Use command line options to change this behaviour.")
	}

	cli.Root.SetArgs([]string{"collect", "activedirectory"})
	err := cli.Root.Execute()
	if err != nil {
		return err
	}

	cli.Root.SetArgs([]string{"analyze"})
	err = cli.Root.Execute()
	return err
}
