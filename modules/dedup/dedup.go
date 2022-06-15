package dedup

import (
	"github.com/OneOfOne/xxhash"
	"github.com/lkarlslund/stringdedup"
)

var D = stringdedup.New(func(in []byte) uint32 {
	return xxhash.Checksum32(in)
})
