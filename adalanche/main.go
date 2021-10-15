package main

import (
	"os"

	"github.com/lkarlslund/adalanche/modules/cli"
	_ "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	_ "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/collect"
	_ "github.com/lkarlslund/adalanche/modules/integrations/localmachine/analyze"
	_ "github.com/lkarlslund/adalanche/modules/quickmode"
	"github.com/rs/zerolog/log"
)

func main() {
	err := cli.Run()

	if err != nil {
		log.Error().Msg(err.Error())
		os.Exit(1)
	}
}
