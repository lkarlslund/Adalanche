//go:build collector
// +build collector

package main

import (
	"os"

	"github.com/lkarlslund/adalanche/modules/cli"
)

func init() {
	// Offer default collect for collector binary
	if len(os.Args[1:]) == 0 {
		cli.OverrideArgs = []string{"collect", "localmachine"}
	}
}
