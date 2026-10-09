package aql

import "github.com/lkarlslund/adalanche/modules/engine"

// pathFilter is a 64-bit bloom filter over the nodes on a search path.
// A clear bit proves a node is not on the path without walking it.
type pathFilter uint64

func pathFilterBit(id engine.NodeIndex) pathFilter {
	return 1 << ((uint32(id) * 0x9E3779B1) >> 26)
}

func (f pathFilter) with(id engine.NodeIndex) pathFilter {
	return f | pathFilterBit(id)
}

func (f pathFilter) mayHave(id engine.NodeIndex) bool {
	return f&pathFilterBit(id) != 0
}
