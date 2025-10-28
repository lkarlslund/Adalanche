package engine

import (
	"bytes"
	"sort"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

type NodeSlice struct {
	nodes []*Node
}

func NewNodeSlice(prealloc int) NodeSlice {
	return NodeSlice{
		nodes: make([]*Node, 0, prealloc),
	}
}

func (ns NodeSlice) Len() int {
	return len(ns.nodes)
}

func (ns *NodeSlice) Add(n *Node) {
	ns.nodes = append(ns.nodes, n)
	// os.objects = append(os.objects, o.ID())
}

func (ns *NodeSlice) Remove(n *Node) {
	for i, cur := range ns.nodes {
		if cur == n {
			if len(ns.nodes) == 1 {
				ns.nodes = nil
			} else {
				ns.nodes[i] = ns.nodes[len(ns.nodes)-1]
				ns.nodes = ns.nodes[:len(ns.nodes)-1]
			}
			return
		}
	}
	panic("Asked to remove item from ObjectSlice that isn't there")
}

func (ns NodeSlice) First() *Node {
	if len(ns.nodes) == 0 {
		return nil
	}
	return ns.nodes[0]
}

func (ns NodeSlice) Iterate(af func(o *Node) bool) {
	if ns.nodes == nil {
		return
	}
	for _, o := range ns.nodes {
		if !af(o) {
			break
		}
	}
}

func (ns *NodeSlice) Sort(attr Attribute, reverse bool) {
	orderf := func(i, j int) bool {
		iv, ifound := ns.nodes[i].Get(attr)
		jv, jfound := ns.nodes[j].Get(attr)

		// No one has attribute, so not less
		if !ifound && !jfound {
			return false
		}
		// Only i does not have, so it is less
		if !ifound {
			return true
		}
		// Only j does not have, so it is not less
		if !jfound {
			return false
		}

		// Both have, so compare
		ir := iv.First().Raw()
		jr := jv.First().Raw()

		switch it := ir.(type) {
		case int64:
			jt, ok := jr.(int64)
			if !ok {
				return false // Not comparable
			}
			return it < jt
		case time.Time:
			jt, ok := jr.(time.Time)
			if !ok {
				return false // Not comparable
			}
			return it.Before(jt)
		case string:
			jt, ok := jr.(string)
			if !ok {
				return false // Not comparable
			}
			return strings.Compare(it, jt) == -1
		case []byte:
			jt, ok := jr.([]byte)
			if !ok {
				return false // Not comparable
			}
			return bytes.Compare(it, jt) == -1
		case bool:
			jt, ok := jr.(bool)
			if !ok {
				return false // Not comparable
			}
			return !it && jt
		case uuid.UUID:
			jt, ok := jr.(uuid.UUID)
			if !ok {
				return false // Not comparable
			}
			return bytes.Compare(it[:], jt[:]) == -1
		case windowssecurity.SID:
			jt, ok := jr.(windowssecurity.SID)
			if !ok {
				return false // Not comparable
			}
			components := min(jt.Components(), it.Components())
			for i := 0; i < components; i++ {
				if it.Component(i) == jt.Component(i) {
					continue
				}
				return it.Component(i) < jt.Component(i)
			}
			return it.Components() < jt.Components()
		}

		return false
	}

	if reverse {
		orderf = func(i, j int) bool {
			return !orderf(i, j)
		}
	}

	sort.Slice(ns.nodes, orderf)
}

func (ns *NodeSlice) SortFunc(lessthan func(o, o2 *Node) bool) {
	sort.Slice(ns.nodes, func(i int, j int) bool {
		return lessthan(ns.nodes[i], ns.nodes[j])
	})
}

func (ns *NodeSlice) Skip(count int) {
	if count > 0 {
		// from start
		if count > len(ns.nodes) {
			ns.nodes = ns.nodes[count:]
		} else {
			ns.nodes = ns.nodes[:0]
		}
	} else if count < 0 {
		// from end
		count = -count
		if count > len(ns.nodes) {
			ns.nodes = ns.nodes[:len(ns.nodes)-count]
		} else {
			ns.nodes = ns.nodes[:0]
		}
	}
}

func (ns *NodeSlice) Limit(count int) {
	if count > 0 {
		if count < len(ns.nodes) {
			ns.nodes = ns.nodes[:count]
		}
	} else if count < 0 {
		count = -count
		if count < len(ns.nodes) {
			ns.nodes = ns.nodes[len(ns.nodes)-count:]
		}
	}
}
