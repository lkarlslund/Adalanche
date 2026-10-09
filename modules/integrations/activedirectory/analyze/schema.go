package analyze

import (
	"sync"

	"github.com/lkarlslund/adalanche/modules/engine"
)

// sameDump keeps the nodes that came from the same directory dump as o.
// Every domain's dump is in one graph, and each forest has
// its own schema, so schema lookups for an object go to its own dump.
func sameDump(nodes engine.NodeSlice, o *engine.Node) engine.NodeSlice {
	source := o.OneAttr(engine.DataSource)
	if source.IsNil() {
		return nodes
	}
	var result engine.NodeSlice
	nodes.Iterate(func(n *engine.Node) bool {
		if n.HasAttrValue(engine.DataSource, source) {
			result.Add(n)
		}
		return true
	})
	return result
}

// schemaObject finds the one schema object with the value in o's dump.
func schemaObject(ao engine.GraphReader, o *engine.Node, attr engine.Attribute, value engine.AttributeValue) (*engine.Node, bool) {
	nodes, _ := ao.FindMulti(attr, value)
	return oneOf(sameDump(nodes, o))
}

// schemaObjectTwo finds the one schema object with both values in o's dump.
func schemaObjectTwo(ao engine.GraphReader, o *engine.Node, attr engine.Attribute, value engine.AttributeValue, attr2 engine.Attribute, value2 engine.AttributeValue) (*engine.Node, bool) {
	nodes, _ := ao.FindTwoMulti(attr, value, attr2, value2)
	return oneOf(sameDump(nodes, o))
}

func oneOf(nodes engine.NodeSlice) (*engine.Node, bool) {
	if nodes.Len() != 1 {
		return nil, false
	}
	return nodes.First(), true
}

// perDump computes a value once for each directory dump, from the first of
// its objects asked about.
type perDump[T any] struct {
	compute func(o *engine.Node) T
	values  map[engine.AttributeValue]T
	lock    sync.Mutex
}

func newPerDump[T any](compute func(o *engine.Node) T) *perDump[T] {
	return &perDump[T]{compute: compute, values: map[engine.AttributeValue]T{}}
}

func (p *perDump[T]) For(o *engine.Node) T {
	source := o.OneAttr(engine.DataSource)
	p.lock.Lock()
	defer p.lock.Unlock()
	if v, found := p.values[source]; found {
		return v
	}
	v := p.compute(o)
	p.values[source] = v
	return v
}
