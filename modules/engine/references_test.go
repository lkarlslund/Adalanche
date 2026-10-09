package engine

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
)

var (
	testStrictKey = NewAttribute("test-strict-key").Flag(Merge)
	testFuzzyKey  = NewAttribute("test-fuzzy-key").Flag(Merge, Fuzzy)
)

func addRefs(g *IndexedGraph, refs ...*Node) {
	for _, r := range refs {
		g.add(r)
	}
}

func real(flex ...any) *Node {
	return NewNode(append([]any{DataSource, "real"}, flex...)...)
}

func TestReferenceFoldsOnlyIntoTheOneMatch(t *testing.T) {
	one := real(testStrictKey, "a")
	twinA, twinB := real(testStrictKey, "b"), real(testStrictKey, "b")
	g := testGraph(one, twinA, twinB)
	toOne, toTwins := NewNode(testStrictKey, "a"), NewNode(testStrictKey, "b")
	addRefs(g, toOne, toTwins)
	merged := resolveReferences(g)
	if merged[toOne] != one {
		t.Error("reference with one match not folded")
	}
	if _, folded := merged[toTwins]; folded || !g.Contains(toTwins) {
		t.Error("reference with several matches was folded instead of kept")
	}
}

func TestReferenceTypesMustAgree(t *testing.T) {
	machine := real(Type, "Machine", testFuzzyKey, "host")
	g := testGraph(machine, real(Type, "Computer", testFuzzyKey, "host"))
	typed, untyped := NewNode(Type, "Machine", testFuzzyKey, "host"), NewNode(testFuzzyKey, "host")
	addRefs(g, typed, untyped)
	merged := resolveReferences(g)
	if merged[typed] != machine {
		t.Error("typed reference did not fold into the node of its type")
	}
	if _, folded := merged[untyped]; folded {
		t.Error("untyped reference folded although two nodes of different types match")
	}
}

func TestStrictKeysDecideBeforeFuzzy(t *testing.T) {
	byStrict, byFuzzy := real(testStrictKey, "s"), real(testFuzzyKey, "f")
	twinA, twinB := real(testStrictKey, "dup"), real(testStrictKey, "dup")
	g := testGraph(byStrict, byFuzzy, twinA, twinB)
	both := NewNode(testStrictKey, "s", testFuzzyKey, "f")
	ambiguous := NewNode(testStrictKey, "dup", testFuzzyKey, "f")
	addRefs(g, both, ambiguous)
	merged := resolveReferences(g)
	if merged[both] != byStrict {
		t.Error("fuzzy key decided before the strict one")
	}
	if _, folded := merged[ambiguous]; folded {
		t.Error("an ambiguous strict key fell back to the fuzzy one")
	}
}

func TestLaterRoundsSeeEarlierFolds(t *testing.T) {
	collection := real(Type, "Machine", testStrictKey, "account")
	g := testGraph(collection)
	// The directory's machine knows the host name; the scanner only that.
	directory := NewNode(Type, "Machine", testStrictKey, "account", testFuzzyKey, "host.example")
	scanner := NewNode(Type, "Machine", testFuzzyKey, "host.example")
	addRefs(g, scanner, directory)
	merged := resolveReferences(g)
	if merged[directory] != collection || merged[scanner] != collection {
		t.Error("references did not both reach the collection")
	}
}

func TestUnresolvedReferencesGroupTheSameInAnyOrder(t *testing.T) {
	build := func() []*Node {
		return []*Node{
			NewNode(Type, "Machine", testFuzzyKey, "10.0.0.1", Name, "x"),
			NewNode(Type, "Machine", testFuzzyKey, []string{"10.0.0.1", "10.0.0.2"}),
			NewNode(Type, "Machine", testFuzzyKey, "10.0.0.2"),
			NewNode(Type, "Group", testFuzzyKey, "10.0.0.1"),
			NewNode(Type, "Machine", testFuzzyKey, "10.0.0.9"),
		}
	}
	shape := func(seed uint64) []string {
		refs := build()
		rand.New(rand.NewPCG(seed, 0)).Shuffle(len(refs), func(i, j int) { refs[i], refs[j] = refs[j], refs[i] })
		g := testGraph()
		addRefs(g, refs...)
		resolveReferences(g)
		var out []string
		g.Iterate(func(n *Node) bool {
			keys := n.Attr(testFuzzyKey).StringSlice()
			slices.Sort(keys)
			out = append(out, fmt.Sprint(n.Type().String(), keys, n.OneAttrString(Name)))
			return true
		})
		slices.Sort(out)
		return out
	}
	want := shape(1)
	if len(want) != 3 {
		t.Fatalf("got %v nodes, want three: the joined machines, the group and the lone machine: %q", len(want), want)
	}
	for seed := uint64(2); seed < 20; seed++ {
		if got := shape(seed); !slices.Equal(got, want) {
			t.Fatalf("order changed the result: %v vs %v", got, want)
		}
	}
}

// A reference scoped to a domain does not stand for a node without one,
// such as a machine's group with the same SID.
func TestDomainScopedReferenceSkipsUnscopedNodes(t *testing.T) {
	domainAdmins := real(testStrictKey, "S-1-5-32-544", DomainContext, "DC=b,DC=test")
	machineAdmins := real(testStrictKey, "S-1-5-32-544")
	g := testGraph(domainAdmins, machineAdmins)
	ref := NewNode(testStrictKey, "S-1-5-32-544", DomainContext, "DC=b,DC=test")
	addRefs(g, ref)
	merged := resolveReferences(g)
	if merged[ref] != domainAdmins {
		t.Error("domain-scoped reference did not resolve to the domain's node")
	}
}
