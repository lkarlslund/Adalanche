package engine

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestScopedSIDsStayInTheirScope(t *testing.T) {
	withProgressDisabled(t)
	system := windowssecurity.LocalSystemSID
	a, b := NewIndexedGraph(), NewIndexedGraph()
	systemA := NewNode(Name, "SYSTEM a", ObjectSid, NV(system), DomainContext, "DC=a", DataSource, "a")
	a.add(systemA)
	targetB := NewNode(Name, "target", DistinguishedName, "CN=target,DC=b", DomainContext, "DC=b", DataSource, "b")
	b.add(targetB)

	g := loadGraphs(a, b)
	if found, ok := g.FindAdjacentSID(system, targetB); ok {
		t.Fatalf("SYSTEM for domain b resolved to %q", found.Label())
	}
	systemB := g.findOrAddAdjacentSID(system, targetB)
	if systemB == systemA || systemB.OneAttrString(DomainContext) != "DC=b" {
		t.Fatalf("SYSTEM for domain b was not added in its own scope: %v", systemB.Label())
	}
	if again := g.findOrAddAdjacentSID(system, targetB); again != systemB {
		t.Fatal("a second lookup in the same scope added another node")
	}
}

func TestDomainSIDStubsMergeIntoTheAccount(t *testing.T) {
	withProgressDisabled(t)
	userSID := windowssecurity.MustParseStringSID("S-1-5-21-10-10-10-1001")
	unknownSID := windowssecurity.MustParseStringSID("S-1-5-21-20-20-20-1001")
	edge := NewEdge("IdentityTestEdge")

	a := NewIndexedGraph()
	user := NewNode(Name, "alice", DistinguishedName, "CN=alice,DC=a", DomainContext, "DC=a", DataSource, "a", ObjectSid, NV(userSID))
	a.add(user)

	// Domains b and c refer to alice and to an account from a forest that
	// was not collected.
	var targets []*Node
	var graphs = []*IndexedGraph{a}
	for _, domain := range []string{"b", "c"} {
		g := NewIndexedGraph()
		target := NewNode(Name, "target "+domain, DistinguishedName, "CN=target,DC="+domain, DomainContext, "DC="+domain, DataSource, domain)
		g.add(target)
		g.edgeTo(g.findOrAddAdjacentSID(userSID, target), target, edge)
		g.edgeTo(g.findOrAddAdjacentSID(unknownSID, target), target, edge)
		targets = append(targets, target)
		graphs = append(graphs, g)
	}

	g := loadGraphs(graphs...)
	if nodes, _ := g.FindMulti(ObjectSid, NV(userSID)); nodes.Len() != 1 {
		t.Fatalf("alice's SID is on %d nodes", nodes.Len())
	}
	unknown, _ := g.FindMulti(ObjectSid, NV(unknownSID))
	if unknown.Len() != 1 {
		t.Fatalf("the uncollected account's SID is on %d nodes", unknown.Len())
	}
	for _, target := range targets {
		if eb, found := g.GetEdge(user, target); !found || !eb.IsSet(edge) {
			t.Errorf("edge from alice to %v was not moved to her node", target.Label())
		}
		if eb, found := g.GetEdge(unknown.First(), target); !found || !eb.IsSet(edge) {
			t.Errorf("edge from the uncollected account to %v is missing", target.Label())
		}
	}
}

func TestStubsForAmbiguousSIDsAreNotGuessed(t *testing.T) {
	withProgressDisabled(t)
	// Two machines cloned with the same machine SID.
	sid := windowssecurity.MustParseStringSID("S-1-5-21-30-30-30-500")
	m1, m2, ref := NewIndexedGraph(), NewIndexedGraph(), NewIndexedGraph()
	admin1 := NewNode(Name, "admin m1", ObjectSid, NV(sid), DataSource, "m1")
	admin2 := NewNode(Name, "admin m2", ObjectSid, NV(sid), DataSource, "m2")
	m1.add(admin1)
	m2.add(admin2)
	target := NewNode(Name, "target", DistinguishedName, "CN=target,DC=x", DomainContext, "DC=x", DataSource, "x")
	ref.add(target)
	stub := ref.findOrAddAdjacentSID(sid, target)

	g := loadGraphs(m1, m2, ref)
	if !g.Contains(stub) || !g.Contains(admin1) || !g.Contains(admin2) {
		t.Fatal("a stub for a SID held by two accounts was merged into one of them")
	}
}

func TestScopeWithDuplicateSIDsDoesNotGrow(t *testing.T) {
	g := NewIndexedGraph()
	sid := windowssecurity.LocalSystemSID
	first := NewNode(Name, "first", ObjectSid, NV(sid), DomainContext, "DC=a")
	g.add(first)
	g.add(NewNode(Name, "second", ObjectSid, NV(sid), DomainContext, "DC=a"))
	target := NewNode(Name, "target", DomainContext, "DC=a")
	g.add(target)
	for range 3 {
		if got := g.findOrAddAdjacentSID(sid, target); got != first {
			t.Fatalf("lookup in a scope with two nodes for the SID returned %v", got.Label())
		}
	}
	if nodes, _ := g.FindMulti(ObjectSid, NV(sid)); nodes.Len() != 2 {
		t.Fatalf("lookups grew the scope to %d nodes", nodes.Len())
	}
}
