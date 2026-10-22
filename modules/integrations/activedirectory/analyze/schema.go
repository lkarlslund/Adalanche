package analyze

import (
	"slices"
	"strings"
	"sync"

	"github.com/gofrs/uuid/v5"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
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

// newPossibleSuperiors finds, per dump, the classes whose objects the schema
// lets an object of class be created in: the possSuperiors and
// systemPossSuperiors of the class, of its superclasses, and of the
// auxiliary classes of either, as MS-ADTS 3.1.1.2.4.5 has it. The value is
// nil for a dump without the class in its schema.
func newPossibleSuperiors(ao engine.GraphReader, class string) *perDump[map[string]bool] {
	return newPerDump(func(o *engine.Node) map[string]bool {
		var superiors map[string]bool
		seen := map[string]bool{}
		queue := []string{class}
		for len(queue) > 0 {
			name := queue[0]
			queue = queue[1:]
			if seen[strings.ToLower(name)] {
				continue
			}
			seen[strings.ToLower(name)] = true
			schema, found := schemaObject(ao, o, activedirectory.LDAPDisplayName, engine.NV(name))
			if !found {
				continue
			}
			if superiors == nil {
				superiors = map[string]bool{}
			}
			for _, attr := range []engine.Attribute{activedirectory.PossSuperiors, activedirectory.SystemPossSuperiors} {
				schema.Attr(attr).Iterate(func(v engine.AttributeValue) bool {
					superiors[strings.ToLower(v.String())] = true
					return true
				})
			}
			for _, attr := range []engine.Attribute{activedirectory.SubClassOf, activedirectory.AuxiliaryClass, activedirectory.SystemAuxiliaryClass} {
				schema.Attr(attr).Iterate(func(v engine.AttributeValue) bool {
					queue = append(queue, v.String())
					return true
				})
			}
		}
		return superiors
	})
}

// hasClassIn tells whether any of o's object classes, which include the
// classes it derives from, is in classes.
func hasClassIn(o *engine.Node, classes map[string]bool) bool {
	var found bool
	o.Attr(engine.ObjectClass).Iterate(func(v engine.AttributeValue) bool {
		found = classes[strings.ToLower(v.String())]
		return !found
	})
	return found
}

// CanContain returns whether the schema lets objects of class be created in
// an object, by its possible superiors (see newPossibleSuperiors), or for a
// dump without the class in its schema, whether the object is of one of the
// fallback types.
func CanContain(ao engine.GraphReader, class string, fallback ...engine.NodeType) func(o *engine.Node) bool {
	superiors := newPossibleSuperiors(ao, class)
	return func(o *engine.Node) bool {
		if classes := superiors.For(o); classes != nil {
			return hasClassIn(o, classes)
		}
		return slices.Contains(fallback, o.Type())
	}
}

// SchemaAttributeGUID returns the schemaIDGUID of the attribute with this
// lDAPDisplayName, in the schema of the dump relativeTo came from.
func SchemaAttributeGUID(ao engine.GraphReader, relativeTo *engine.Node, ldapName string) (uuid.UUID, bool) {
	schema, found := schemaObject(ao, relativeTo, activedirectory.LDAPDisplayName, engine.NV(ldapName))
	if !found {
		return uuid.Nil, false
	}
	guid, ok := schema.OneAttrRaw(activedirectory.SchemaIDGUID).(uuid.UUID)
	return guid, ok
}
