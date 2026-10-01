package main

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
)

// Every processor linked into the binary must have its needs met and no
// dependency cycles.
func TestRegisteredProcessorsCanBeOrdered(t *testing.T) {
	if err := engine.ValidateProcessors(); err != nil {
		t.Fatal(err)
	}
}
