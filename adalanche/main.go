package main

import (
	"os"

	"github.com/lkarlslund/adalanche/modules/cli"
	_ "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	_ "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/collect"
	_ "github.com/lkarlslund/adalanche/modules/integrations/localmachine/analyze"
	_ "github.com/lkarlslund/adalanche/modules/quickmode"
	"github.com/lkarlslund/adalanche/modules/ui"
)

func main() {
	err := cli.CliMainEntryPoint()

	if err != nil {
		ui.Error().Msg(err.Error())
		os.Exit(1)
	}
}
