package aql

import "github.com/lkarlslund/adalanche/modules/engine"

const bloomSize = 32
const bloomItemSize = 8
const totalBits = bloomSize * bloomItemSize

type bloom [bloomSize]byte

// Calculate a bit to set or test
func (b *bloom) hash(item engine.NodeID) int {
	// incoming item value is a pointer, so mix it up a bit
	hash := int(item ^ item>>17 ^ item>>31)

	// map it to a specific bit in the bloom filter array
	bit := hash % totalBits
	return bit
}

func (b *bloom) Add(item engine.NodeID) {
	// hash the value to a given bit
	bit := b.hash(item)
	b[bit/bloomItemSize] |= 1 << (bit % bloomItemSize)
}

func (b *bloom) Has(item engine.NodeID) bool {
	// hash the value to a given bit
	bit := b.hash(item)
	return b[bit/bloomItemSize]&(1<<(bit%bloomItemSize)) != 0
}
