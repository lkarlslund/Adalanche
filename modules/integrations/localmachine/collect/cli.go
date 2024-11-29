package collect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lkarlslund/adalanche/modules/cli"
	clicollect "github.com/lkarlslund/adalanche/modules/cli/collect"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/spf13/cobra"
)

var (
	Cmd = &cobra.Command{
		Use:   "localmachine",
		Short: "Gathers local information about a machine in the network (deploy with a sch.task via GPO for efficiency)",
		RunE:  Execute,
	}
)

func init() {
	clicollect.Collect.AddCommand(Cmd)
}

func Execute(cmd *cobra.Command, args []string) error {
	datapath := *cli.Datapath

	err := os.MkdirAll(datapath, 0600)
	if err != nil {
		return fmt.Errorf("Problem accessing output folder: %v", err)
	}

	info, err := Collect()
	if err != nil {
		return err
	}

	targetname := info.Machine.Name + localmachine.Suffix
	if info.Machine.IsDomainJoined {
		targetname = info.Machine.Name + "$" + info.Machine.Domain + localmachine.Suffix
	}
	output, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("Problem marshalling JSON: %v", err)
	}

	outputfile := filepath.Join(datapath, targetname)
	err = os.WriteFile(outputfile, output, 0600)
	if err != nil {
		return fmt.Errorf("Problem writing to file %v: %v", outputfile, err)
	}
	ui.Info().Msgf("Information collected to file %v", outputfile)
	return nil
}
