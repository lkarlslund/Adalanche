//go:build !collector
// +build !collector

package main

import (
	_ "github.com/lkarlslund/adalanche/modules/aql"
	_ "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	_ "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/collect"
	_ "github.com/lkarlslund/adalanche/modules/integrations/localmachine/analyze"
	_ "github.com/lkarlslund/adalanche/modules/quickmode"
)
