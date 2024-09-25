package main

import (
	"os"

	"github.com/lkarlslund/adalanche/modules/cli"
	"github.com/lkarlslund/adalanche/modules/ui"
)

func main() {
	err := cli.CliMainEntryPoint()

	if err != nil {
		ui.Error().Msg(err.Error())
		os.Exit(1)
	}
}
