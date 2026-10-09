package engine

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/adalanche/modules/ui"
)

// A reference is a node with no identity of its own: no data source and no
// distinguished name shared with a real node. It names something by a key,
// such as a SID, a logon name, a GPO path or an address. resolveReferences
// folds each reference into the one real node it names, or keeps it.
//
// The rules decide only on data, never on the order nodes arrive in:
//   - Keys are tried strict first (Merge), then fuzzy (Merge and Fuzzy),
//     each in attribute order. The first key with any match decides.
//   - A reference folds into a real node only when exactly one compatible
//     real node matches: the same type (or either is untyped), the same
//     domain context when the reference has one, and no single-valued
//     attribute whose value the node lacks. Several matches leave the
//     reference on its own, counted as ambiguous.
//   - Matching runs in rounds against the real nodes as they were at the
//     start of the round, so folds in one round never steer others in it.
//     A later round sees what earlier folds brought (a machine from the
//     directory folding into its collection brings its host name).
//   - References that resolve to nothing are grouped with references of
//     the same type sharing a key value, and each group becomes one node.
//
// It works in place: folded references leave the graph, and their edges
// move to the node they stand for. It returns what was folded into what.
func resolveReferences(g *IndexedGraph) map[*Node]*Node {
	return resolveReferencesRemoving(g, nil)
}

// resolveReferencesRemoving is resolveReferences that also removes the given
// nodes in the same compaction.
func resolveReferencesRemoving(g *IndexedGraph, remove []*Node) map[*Node]*Node {
	keys := referenceKeys()
	conflicts := getConflictAttributes()
	merged := map[*Node]*Node{}
	for _, n := range remove {
		merged[n] = nil
	}

	var unresolved []*Node
	g.Iterate(func(n *Node) bool {
		if isReference(n) && hasAnyKey(n, keys) {
			unresolved = append(unresolved, n)
		}
		return true
	})

	folded := map[Attribute]int{}
	ambiguous := map[Attribute]int{}
	for round := 1; len(unresolved) > 0; round++ {
		targets := make([]*Node, len(unresolved))
		decidedBy := make([]Attribute, len(unresolved))
		several := make([]bool, len(unresolved))
		var wg sync.WaitGroup
		const chunk = 1024
		candidates := &realCandidates{g: g}
		for start := 0; start < len(unresolved); start += chunk {
			wg.Go(func() {
				for i := start; i < min(start+chunk, len(unresolved)); i++ {
					targets[i], decidedBy[i], several[i] = matchReference(candidates, unresolved[i], keys, conflicts)
				}
			})
		}
		wg.Wait()

		var next []*Node
		touched := map[*Node]struct{}{}
		for i, ref := range unresolved {
			if t := targets[i]; t != nil {
				t.foldInto(ref)
				merged[ref] = t
				touched[t] = struct{}{}
				folded[decidedBy[i]]++
				continue
			}
			next = append(next, ref)
		}
		for t := range touched {
			g.reindexObject(t, false)
		}
		if len(touched) == 0 {
			for i := range unresolved {
				if several[i] {
					ambiguous[decidedBy[i]]++
				}
			}
			break
		}
		unresolved = next
	}

	groups := groupReferences(unresolved, keys, conflicts)
	for _, group := range groups {
		rep := group[0]
		for _, other := range group[1:] {
			rep.foldInto(other)
			merged[other] = rep
		}
	}
	compactStart := time.Now()
	g.compact(merged)
	// What was folded into a node may have been all the indexes knew of it
	// (a unique index keeps only the first node with a value).
	targets := map[*Node]struct{}{}
	for _, t := range merged {
		if t != nil {
			targets[t] = struct{}{}
		}
	}
	for t := range targets {
		if g.Contains(t) {
			g.reindexObject(t, false)
		}
	}
	ui.Info().Msgf("Finishing loading: compaction took %v", time.Since(compactStart))

	for a, n := range folded {
		ui.Info().Msgf("References resolved by %v: %v", a.String(), n)
	}
	for a, n := range ambiguous {
		ui.Warn().Msgf("References left on their own because %v matched several nodes: %v", a.String(), n)
	}
	ui.Info().Msgf("Unresolved references: %v, joined into %v nodes", len(unresolved), len(groups))
	return merged
}

// isReference reports whether a node only stands for something: it has no
// data source of its own.
func isReference(n *Node) bool {
	return !n.HasAttr(DataSource)
}

// referenceKeys lists the merge keys, strict before fuzzy.
func referenceKeys() []Attribute {
	var strict, fuzzy []Attribute
	for a := range attributeinfos {
		attr := Attribute(a)
		switch {
		case !attr.HasFlag(Merge):
		case attr.HasFlag(Fuzzy):
			fuzzy = append(fuzzy, attr)
		default:
			strict = append(strict, attr)
		}
	}
	return append(strict, fuzzy...)
}

func hasAnyKey(n *Node, keys []Attribute) bool {
	for _, a := range keys {
		if n.HasAttr(a) {
			return true
		}
	}
	return false
}

// compatibleReference reports whether ref may stand for node.
func compatibleReference(ref, node *Node, conflicts []Attribute) bool {
	if ref == node {
		return false
	}
	if rt, nt := ref.Type(), node.Type(); rt != NodeTypeOther && nt != NodeTypeOther && rt != nt {
		return false
	}
	// A reference scoped to a domain stands only for that domain's node,
	// never for one that has no domain context (such as a machine's).
	if rc := ref.OneAttr(DomainContext); !rc.IsNil() && !CompareAttributeValues(rc, node.OneAttr(DomainContext)) {
		return false
	}
	// A single-valued attribute conflicts when the reference's value is not
	// among the node's (which can hold several after earlier folds).
	for _, a := range conflicts {
		rv, nv := ref.Attr(a), node.Attr(a)
		if rv.Len() > 0 && nv.Len() > 0 && !slices.ContainsFunc(nv, func(v AttributeValue) bool { return CompareAttributeValues(v, rv.First()) }) {
			return false
		}
	}
	return true
}

// realCandidates finds the real nodes with a key value, once per value in a
// round: many references often name the same thing (an account seen from
// every machine), and each would otherwise walk all the others.
type realCandidates struct {
	g     *IndexedGraph
	found shardedMap[candidateKey, []*Node]
}

type candidateKey struct {
	attr          Attribute
	value, domain AttributeValue
}

// get returns the real nodes with the value, among the domain's nodes when
// domain is set.
func (rc *realCandidates) get(a Attribute, v, domain AttributeValue) []*Node {
	key := candidateKey{a, v, domain}
	if nodes, found := rc.found.Load(key); found {
		return nodes
	}
	var found NodeSlice
	if domain.IsNil() || a == DomainContext {
		found, _ = rc.g.FindMulti(a, v)
	} else {
		found, _ = rc.g.FindTwoMulti(a, v, DomainContext, domain)
	}
	var real []*Node
	found.Iterate(func(n *Node) bool {
		if !isReference(n) {
			real = append(real, n)
		}
		return true
	})
	rc.found.Store(key, real)
	return real
}

// matchReference finds the one real node ref names. It returns the key that
// decided, and whether that key matched several nodes.
func matchReference(candidates *realCandidates, ref *Node, keys, conflicts []Attribute) (*Node, Attribute, bool) {
	// A reference scoped to a domain only matches that domain's nodes, so
	// they are looked up directly: a shared SID such as a builtin group's
	// otherwise brings every machine's copy along.
	domain := ref.OneAttr(DomainContext)
	for _, a := range keys {
		values := ref.Attr(a)
		if values.Len() == 0 {
			continue
		}
		var match *Node
		var count int
		values.Iterate(func(v AttributeValue) bool {
			for _, n := range candidates.get(a, v, domain) {
				if n != match && compatibleReference(ref, n, conflicts) {
					match = n
					count++
					if count > 1 {
						break
					}
				}
			}
			return count < 2
		})
		switch {
		case count == 1:
			return match, a, false
		case count > 1:
			return nil, a, true
		}
	}
	return nil, NonExistingAttribute, false
}

// groupReferences joins unresolved references of the same type that share
// a key value. The order of references within and between groups comes
// from their content, so the result does not depend on arrival order.
func groupReferences(refs []*Node, keys, conflicts []Attribute) [][]*Node {
	// Keys first, then everything else about the node, so that which node
	// of a group is kept never comes from arrival order.
	sortKey := func(n *Node) string {
		var b strings.Builder
		b.WriteString(n.Type().String())
		for _, a := range keys {
			b.WriteByte(0)
			n.Attr(a).Iterate(func(v AttributeValue) bool {
				b.WriteString(strings.ToLower(v.String()))
				b.WriteByte(1)
				return true
			})
		}
		b.WriteByte(2)
		b.WriteString(fmt.Sprint(n.ValueMap()))
		if p := n.Parent(); p != nil {
			b.WriteByte(3)
			b.WriteString(p.DN() + "\x00" + p.Label())
		}
		return b.String()
	}
	type entry struct {
		node *Node
		key  string
	}
	entries := make([]entry, len(refs))
	for i, n := range refs {
		entries[i] = entry{n, sortKey(n)}
	}
	slices.SortStableFunc(entries, func(a, b entry) int { return cmp.Compare(a.key, b.key) })

	parent := make([]int, len(entries))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	seen := map[string]int{}
	for i, e := range entries {
		for _, a := range keys {
			e.node.Attr(a).Iterate(func(v AttributeValue) bool {
				k := e.node.Type().String() + "\x00" + a.String() + "\x00" + strings.ToLower(v.String())
				j, found := seen[k]
				if !found {
					seen[k] = i
					return true
				}
				ri, rj := find(i), find(j)
				if ri != rj && compatibleReference(entries[ri].node, entries[rj].node, conflicts) &&
					compatibleReference(entries[rj].node, entries[ri].node, conflicts) {
					parent[max(ri, rj)] = min(ri, rj)
				}
				return true
			})
		}
	}
	byRoot := map[int][]*Node{}
	var roots []int
	for i, e := range entries {
		r := find(i)
		if _, found := byRoot[r]; !found {
			roots = append(roots, r)
		}
		byRoot[r] = append(byRoot[r], e.node)
	}
	groups := make([][]*Node, 0, len(roots))
	for _, r := range roots {
		groups = append(groups, byRoot[r])
	}
	return groups
}
