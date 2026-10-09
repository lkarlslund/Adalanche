package cli

import (
	"encoding/json"

	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

func init() {
	command := &cobra.Command{Use: "collections", Short: "Inspect collection artifacts without loading the graph"}
	verify := &cobra.Command{
		Use: "verify PATH", Short: "Verify new-format files and run manifests; output counts only", Args: cobra.ExactArgs(1),
		// Verification is read-only and must not initialize collection output or profiling.
		PersistentPreRunE:  standaloneCollectionCommand,
		PersistentPostRunE: func(*cobra.Command, []string) error { return nil },
		RunE: func(cmd *cobra.Command, args []string) error {
			summary, verifyErr := collection.VerifyPath(args[0])
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(summary); err != nil {
				return err
			}
			return verifyErr
		},
	}
	command.AddCommand(verify)
	convert := &cobra.Command{
		Use: "convert SOURCE TARGET", Short: "Convert a legacy collection without changing the source", Args: cobra.ExactArgs(2),
		PersistentPreRunE:  standaloneCollectionCommand,
		PersistentPostRunE: func(*cobra.Command, []string) error { return nil },
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := collection.ConvertFile(args[0], args[1]); err != nil {
				return err
			}
			summary, err := collection.VerifyPath(args[1])
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(summary)
		},
	}
	command.AddCommand(convert)
	Root.AddCommand(command)
}

func standaloneCollectionCommand(cmd *cobra.Command, _ []string) error {
	ui.SetLoglevel(ui.LevelError)
	pterm.Error.Writer = cmd.ErrOrStderr()
	return nil
}
