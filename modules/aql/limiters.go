package aql

import "github.com/lkarlslund/adalanche/modules/engine"

type SkipLimiter int

func (sl SkipLimiter) Limit(o engine.NodeSlice) engine.NodeSlice {
	new := o
	new.Skip(int(sl))
	return new
}

type FirstLimiter int

func (fl FirstLimiter) Limit(o engine.NodeSlice) engine.NodeSlice {
	new := o
	new.Limit(int(fl))
	return new
}
