package engine

import (
	"reflect"

	"github.com/lkarlslund/adalanche/modules/ui"
)

type nodePatchOpKind int

const (
	nodePatchOpSet nodePatchOpKind = iota
	nodePatchOpAddTag
	nodePatchOpClear
)

type nodePatchOp struct {
	kind   nodePatchOpKind
	node   *Node
	attr   Attribute
	values AttributeValues
	tag    string
}

type NodePatchSet struct {
	ops []nodePatchOp
}

func (ps *NodePatchSet) Set(node *Node, attr Attribute, values ...AttributeValue) {
	ps.ops = append(ps.ops, nodePatchOp{
		kind:   nodePatchOpSet,
		node:   node,
		attr:   attr,
		values: append(AttributeValues(nil), values...),
	})
}

func (ps *NodePatchSet) SetFlex(node *Node, flexInit ...any) {
	for _, patch := range expandFlexInit(flexInit...) {
		ps.ops = append(ps.ops, nodePatchOp{
			kind:   nodePatchOpSet,
			node:   node,
			attr:   patch.attr,
			values: patch.values,
		})
	}
}

func (ps *NodePatchSet) AddTag(node *Node, tag string) {
	ps.ops = append(ps.ops, nodePatchOp{
		kind: nodePatchOpAddTag,
		node: node,
		tag:  tag,
	})
}

func (ps *NodePatchSet) Clear(node *Node, attr Attribute) {
	ps.ops = append(ps.ops, nodePatchOp{
		kind: nodePatchOpClear,
		node: node,
		attr: attr,
	})
}

func (ps *NodePatchSet) HasOperations() bool {
	return len(ps.ops) > 0
}

func (ps *NodePatchSet) Apply(ao *IndexedGraph) {
	if len(ps.ops) == 0 {
		return
	}

	firstNode := ps.ops[0].node
	allSameNode := true
	for _, op := range ps.ops[1:] {
		if op.node != firstNode {
			allSameNode = false
			break
		}
	}
	if allSameNode {
		firstNode.values.mu.Lock()
		applyNodePatchOps(firstNode, ps.ops)
		firstNode.values.mu.Unlock()
		return
	}

	grouped := make(map[*Node][]nodePatchOp, len(ps.ops))
	order := make([]*Node, 0, len(ps.ops))
	for _, op := range ps.ops {
		if _, found := grouped[op.node]; !found {
			order = append(order, op.node)
		}
		grouped[op.node] = append(grouped[op.node], op)
	}

	for _, node := range order {
		node.values.mu.Lock()
		applyNodePatchOps(node, grouped[node])
		node.values.mu.Unlock()
	}
}

func applyNodePatchOps(node *Node, ops []nodePatchOp) {
	for _, op := range ops {
		switch op.kind {
		case nodePatchOpSet:
			node.setNoLock(op.attr, op.values)
		case nodePatchOpAddTag:
			if !node.hasTagNoLock(op.tag) {
				node.addNoLock(Tag, AttributeValues{NV(op.tag)})
			}
		case nodePatchOpClear:
			node.values.clear(op.attr)
		}
	}
}

type nodePatchAttrValues struct {
	attr   Attribute
	values AttributeValues
}

func expandFlexInit(flexinit ...any) []nodePatchAttrValues {
	var (
		ignoreBlanks bool
		attribute    = NonExistingAttribute
		values       AttributeValues
		patches      []nodePatchAttrValues
	)

	flush := func() {
		if attribute == NonExistingAttribute || (ignoreBlanks && len(values) == 0) {
			return
		}
		patches = append(patches, nodePatchAttrValues{
			attr:   attribute,
			values: append(AttributeValues(nil), values...),
		})
		values = values[:0]
	}

	for _, item := range flexinit {
		if item == IgnoreBlanks {
			ignoreBlanks = true
			continue
		}
		if item == nil || (reflect.ValueOf(item).Kind() == reflect.Ptr && reflect.ValueOf(item).IsNil()) {
			if ignoreBlanks {
				continue
			}
			ui.Fatal().Msgf("Flex initialization with NIL value")
		}

		switch value := item.(type) {
		case *[]string:
			if value == nil {
				continue
			}
			if ignoreBlanks && len(*value) == 0 {
				continue
			}
			for _, s := range *value {
				if ignoreBlanks && s == "" {
					continue
				}
				values = append(values, NV(s))
			}
		case []string:
			if ignoreBlanks && len(value) == 0 {
				continue
			}
			for _, s := range value {
				if ignoreBlanks && s == "" {
					continue
				}
				values = append(values, NV(s))
			}
		case []AttributeValue:
			for _, attrValue := range value {
				if ignoreBlanks && attrValue.IsZero() {
					continue
				}
				values = append(values, attrValue)
			}
		case AttributeValues:
			for _, attrValue := range value {
				if ignoreBlanks && attrValue.IsZero() {
					continue
				}
				values = append(values, attrValue)
			}
		case Attribute:
			flush()
			attribute = value
		default:
			if reflect.ValueOf(item).Kind() == reflect.Ptr {
				item = reflect.ValueOf(item).Elem().Interface()
			}

			newValue := NV(item)
			if newValue.IsNil() || (ignoreBlanks && newValue.IsZero()) {
				if ignoreBlanks {
					continue
				}
				ui.Fatal().Msgf("Flex initialization with NIL value")
			}
			values = append(values, newValue)
		}
	}

	flush()
	return patches
}

type edgeDeltaOpKind int

const (
	edgeDeltaOpAdd edgeDeltaOpKind = iota
	edgeDeltaOpClear
	edgeDeltaOpSet
)

type edgeDeltaOp struct {
	kind       edgeDeltaOpKind
	from       *Node
	to         *Node
	edge       Edge
	edgeBitmap EdgeBitmap
	force      bool
	merge      bool
}

type EdgeDelta struct {
	ops []edgeDeltaOp
}

func (ed *EdgeDelta) Add(from, to *Node, edge Edge, force bool) {
	ed.ops = append(ed.ops, edgeDeltaOp{
		kind:  edgeDeltaOpAdd,
		from:  from,
		to:    to,
		edge:  edge,
		force: force,
	})
}

func (ed *EdgeDelta) Clear(from, to *Node, edge Edge) {
	ed.ops = append(ed.ops, edgeDeltaOp{
		kind: edgeDeltaOpClear,
		from: from,
		to:   to,
		edge: edge,
	})
}

func (ed *EdgeDelta) Set(from, to *Node, eb EdgeBitmap, merge bool) {
	ed.ops = append(ed.ops, edgeDeltaOp{
		kind:       edgeDeltaOpSet,
		from:       from,
		to:         to,
		edgeBitmap: eb,
		merge:      merge,
	})
}

func (ed *EdgeDelta) Apply(ao *IndexedGraph) {
	mutations := make([]nodeEdgeMutation, 0, len(ed.ops))
	for _, op := range ed.ops {
		switch op.kind {
		case edgeDeltaOpAdd:
			mutations = append(mutations, nodeEdgeMutation{
				From:  op.from,
				To:    op.to,
				Edge:  op.edge,
				Merge: true,
				Force: op.force,
			})
		case edgeDeltaOpClear:
			mutations = append(mutations, nodeEdgeMutation{
				From:  op.from,
				To:    op.to,
				Edge:  op.edge,
				Merge: true,
				Clear: true,
			})
		case edgeDeltaOpSet:
			mutations = append(mutations, nodeEdgeMutation{
				From:       op.from,
				To:         op.to,
				Edge:       NonExistingEdge,
				EdgeBitmap: op.edgeBitmap,
				Merge:      op.merge,
			})
		}
	}
	ao.applyIndexedEdgeMutations(ao.resolveEdgeMutations(mutations))
}
