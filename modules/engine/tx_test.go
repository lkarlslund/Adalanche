package engine

import (
	"fmt"
	"strings"
	"testing"

	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestTxWritesAppearOnlyAtCommit(t *testing.T) {
	alice := NewNode(Name, "alice", DistinguishedName, "CN=alice,DC=a")
	g := testGraph(alice)
	edge := testEdge("tx-edge")

	tx := g.Begin("test")
	group, found := tx.FindOrAdd(DistinguishedName, NV("CN=group,DC=a"), Name, "group")
	if found {
		t.Fatal("new group reported as found")
	}
	tx.Node(alice).Tag("staged")
	tx.EdgeTo(alice, group, edge)

	if again, found := tx.FindOrAdd(DistinguishedName, NV("CN=group,DC=a")); !found || again.Node() != group.Node() {
		t.Fatal("a second FindOrAdd in the transaction did not return the staged node")
	}
	if seen, found := tx.Find(DistinguishedName, NV("CN=group,DC=a")); !found || seen != group.Node() {
		t.Fatal("Find in the transaction does not see its staged node")
	}
	if _, found := g.Find(DistinguishedName, NV("CN=group,DC=a")); found {
		t.Fatal("the graph has the staged node before commit")
	}
	if alice.HasTag("staged") {
		t.Fatal("a write reached the graph before commit")
	}
	if !tx.Node(alice).Node().HasTag("staged") {
		t.Fatal("the transaction does not see its own write")
	}

	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	committed, found := g.Find(DistinguishedName, NV("CN=group,DC=a"))
	if !found || committed.OneAttrString(Name) != "group" {
		t.Fatal("the staged node was not added")
	}
	if !alice.HasTag("staged") {
		t.Fatal("the write was not applied")
	}
	if eb, found := g.GetEdge(alice, committed); !found || !eb.IsSet(edge) {
		t.Fatal("the edge was not applied")
	}
}

func TestTransactionsStagingTheSameNodeShareIt(t *testing.T) {
	g := testGraph(NewNode(Name, "root"))
	sid := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1001")
	a, b := g.Begin("a"), g.Begin("b")
	inA, _ := a.FindOrAdd(ObjectSid, NV(sid))
	inA.Tag("from a")
	inB, _ := b.FindOrAdd(ObjectSid, NV(sid))
	inB.Tag("from b")
	if err := g.Commit(a, b); err != nil {
		t.Fatal(err)
	}
	nodes, _ := g.FindMulti(ObjectSid, NV(sid))
	if nodes.Len() != 1 {
		t.Fatalf("two transactions staging the same node gave %d nodes", nodes.Len())
	}
	if n := nodes.First(); !n.HasTag("from a") || !n.HasTag("from b") {
		t.Fatal("writes from both transactions were not combined")
	}
}

func TestConflictingSetsAreReported(t *testing.T) {
	node := NewNode(Name, "node")
	g := testGraph(node)
	a, b := g.Begin("first"), g.Begin("second")
	a.Node(node).Set(DisplayName, NV("one"))
	b.Node(node).Set(DisplayName, NV("two"))
	err := g.Commit(a, b)
	if err == nil || !strings.Contains(err.Error(), "first") || !strings.Contains(err.Error(), "second") {
		t.Fatalf("expected a conflict naming both transactions, got %v", err)
	}

	same, also := g.Begin("first"), g.Begin("second")
	same.Node(node).Set(DisplayName, NV("three"))
	also.Node(node).Set(DisplayName, NV("three"))
	if err := g.Commit(same, also); err != nil {
		t.Fatalf("setting the same value was reported as a conflict: %v", err)
	}
}

func TestTxEdgeFiltersMatchEdgeTo(t *testing.T) {
	sid := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1001")
	a := NewNode(Name, "a", ObjectSid, NV(sid))
	twin := NewNode(Name, "twin", ObjectSid, NV(sid))
	g := testGraph(a, twin)
	edge := testEdge("tx-filter")
	tx := g.Begin("test")
	tx.EdgeTo(a, a, edge)
	tx.EdgeTo(a, twin, edge)
	tx.EdgeToEx(twin, a, edge, true)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, found := g.GetEdge(a, a); found {
		t.Fatal("edge to itself was added")
	}
	if _, found := g.GetEdge(a, twin); found {
		t.Fatal("edge between nodes for the same SID was added without force")
	}
	if _, found := g.GetEdge(twin, a); !found {
		t.Fatal("forced edge between nodes for the same SID was not added")
	}
}

func TestTxChildOfResolvesStagedParents(t *testing.T) {
	child := NewNode(Name, "child", DistinguishedName, "CN=child,OU=new,DC=a")
	g := testGraph(child)
	tx := g.Begin("test")
	parent := tx.AddNew(DistinguishedName, "OU=new,DC=a")
	tx.Node(child).ChildOf(parent)
	if found, ok := tx.DistinguishedParent(child); !ok || found != parent.Node() {
		t.Fatal("DistinguishedParent does not see the staged parent")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if child.Parent() == nil || child.Parent().DN() != "OU=new,DC=a" {
		t.Fatal("parent link was not applied")
	}
}

func TestForkedTransactionsJoinInOrder(t *testing.T) {
	nodes := []*Node{NewNode(Name, "a"), NewNode(Name, "b"), NewNode(Name, "c")}
	g := testGraph(nodes...)
	sid := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1001")
	edge := testEdge("fork-edge")
	tx := g.Begin("test")
	forks := tx.Fork(len(nodes))
	for i, f := range forks {
		principal, _ := f.FindOrAdd(ObjectSid, NV(sid))
		f.EdgeTo(principal, nodes[i], edge)
	}
	tx.Join(forks)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	principals, _ := g.FindMulti(ObjectSid, NV(sid))
	if principals.Len() != 1 {
		t.Fatalf("forks staging the same SID gave %d nodes", principals.Len())
	}
	for _, n := range nodes {
		if _, found := g.GetEdge(principals.First(), n); !found {
			t.Fatalf("edge to %v from a fork is missing", n.Label())
		}
	}
}

func TestSIDRelativeToStagedNodeUsesItsAttributes(t *testing.T) {
	g := testGraph(NewNode(Name, "root"))
	stage := func(name string) {
		tx := g.Begin(name)
		machine, _ := tx.FindOrAdd(Name, NV(name))
		machine.SetFlex(Type, "Machine", DataSource, name)
		everyone := tx.FindOrAddAdjacentSID(windowssecurity.EveryoneSID, machine)
		everyone.SetFlex(Type, "Group")
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	stage("m1")
	stage("m2")
	nodes, _ := g.FindMulti(ObjectSid, NV(windowssecurity.EveryoneSID))
	if nodes.Len() != 2 {
		t.Fatalf("Everyone for two machines gave %d nodes", nodes.Len())
	}
	for _, source := range []string{"m1", "m2"} {
		if _, found := g.FindTwo(ObjectSid, NV(windowssecurity.EveryoneSID), DataSource, NV(source)); !found {
			t.Errorf("no Everyone scoped to %v", source)
		}
	}
}

func TestLaterTransactionFindsNodeByAttributeSetEarlierInCommit(t *testing.T) {
	g := testGraph(NewNode(Name, "root"))
	// Build the index first, so it would be stale without reindexing.
	g.FindMulti(DistinguishedName, NV("CN=x"))
	first, second := g.Begin("first"), g.Begin("second")
	created := first.AddNew(Name, "created")
	created.Set(DistinguishedName, NV("CN=x"))
	again, _ := second.FindOrAdd(DistinguishedName, NV("CN=x"))
	again.Tag("from second")
	if err := g.Commit(first, second); err != nil {
		t.Fatal(err)
	}
	nodes, _ := g.FindMulti(DistinguishedName, NV("CN=x"))
	if nodes.Len() != 1 || !nodes.First().HasTag("from second") {
		t.Fatalf("got %d nodes for the DN; the second transaction did not find the first's node", nodes.Len())
	}
}

// A SID looked up relative to a machine finds a node the same transaction
// staged with that SID in the machine's scope, as the graph lookup would.
func TestSIDLookupFindsStagedNodesInScope(t *testing.T) {
	g := testGraph()
	machineSID := windowssecurity.MustParseStringSID("S-1-5-21-10-20-30")
	userSID := windowssecurity.MustParseStringSID("S-1-5-21-10-20-30-1001")
	builtinSID := windowssecurity.MustParseStringSID("S-1-5-32-544")

	tx := g.Begin("machine")
	machine := tx.AddNew(Type, NodeTypeMachine.ValueString(), ObjectSid, NVSID(machineSID), DataSource, "host")
	user := tx.AddNew(ObjectSid, NVSID(userSID), DataSource, "host")
	group := tx.AddNew(ObjectSid, NVSID(builtinSID), DataSource, "host")
	other := tx.AddNew(ObjectSid, NVSID(builtinSID), DataSource, "elsewhere")

	if found, ok := tx.FindOrAddAdjacentSIDFound(userSID, machine); !ok || found.Node() != user.Node() {
		t.Error("local account staged in the machine's scope not found")
	}
	if found, ok := tx.FindOrAddAdjacentSIDFound(builtinSID, machine); !ok || found.Node() != group.Node() {
		t.Error("builtin group staged in the machine's scope not found")
	}
	if found, ok := tx.FindAdjacentSID(builtinSID, machine.Node()); !ok || found == other.Node() {
		t.Error("lookup crossed into another scope")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if nodes, _ := g.FindMulti(ObjectSid, NVSID(userSID)); nodes.Len() != 1 {
		t.Errorf("got %v nodes for the local account, want 1", nodes.Len())
	}
	if nodes, _ := g.FindMulti(ObjectSid, NVSID(builtinSID)); nodes.Len() != 2 {
		t.Errorf("got %v nodes for the builtin group, want one per scope", nodes.Len())
	}
}

// Forks of one transaction commit together without conflict checks, and
// their attribute writes to existing nodes are applied in parallel with the
// same result as one by one.
func TestForkedAttributeWritesCommitInOrder(t *testing.T) {
	g := testGraph()
	nodes := make([]*Node, 20000)
	for i := range nodes {
		nodes[i] = NewNode(Name, NV(fmt.Sprintf("n%d", i)))
		g.add(nodes[i])
	}
	_ = g.GetIndex(Description) // an index the writes must not leave stale

	forks := g.Begin("compute").Fork(8)
	for i, n := range nodes {
		forks[i%8].Node(n).Set(Description, NV(fmt.Sprintf("d%d", i))).Tag("computed")
	}
	// The same node written by two forks: the later fork's write wins.
	forks[2].Node(nodes[0]).Set(DisplayName, NV("first"))
	forks[5].Node(nodes[0]).Set(DisplayName, NV("second"))
	if err := g.Commit(forks...); err != nil {
		t.Fatal(err)
	}
	for i, n := range nodes {
		if got := n.OneAttrString(Description); got != fmt.Sprintf("d%d", i) || !n.HasTag("computed") {
			t.Fatalf("node %d: description %q", i, got)
		}
	}
	if got := nodes[0].OneAttrString(DisplayName); got != "second" {
		t.Errorf("display name %q, want the later fork's", got)
	}
	if found, ok := g.Find(Description, NV("d12345")); !ok || found != nodes[12345] {
		t.Error("index not up to date after a parallel commit")
	}
}

// SetMany writes several attributes as one op, on both commit paths, and a
// different value from another transaction is still a conflict.
func TestSetManyWritesEachAttribute(t *testing.T) {
	a, b := NewNode(Name, "a"), NewNode(Name, "b")
	g := testGraph(a, b)
	attrs := []Attribute{Description, DisplayName}

	tx := g.Begin("one")
	tx.Node(a).SetMany(attrs, []AttributeValue{NV("desc"), NV("display")})
	if got := tx.Node(a).Node().OneAttrString(DisplayName); got != "display" {
		t.Errorf("transaction view %q", got)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if a.OneAttrString(Description) != "desc" || a.OneAttrString(DisplayName) != "display" {
		t.Error("SetMany not applied")
	}

	first, second := g.Begin("first"), g.Begin("second")
	first.Node(b).SetMany(attrs, []AttributeValue{NV("x"), NV("y")})
	second.Node(b).Set(DisplayName, NV("other"))
	if err := g.Commit(first, second); err == nil || !strings.Contains(err.Error(), "dependency") {
		t.Errorf("conflict through SetMany not reported: %v", err)
	}
}

// Clearing objectSid through a transaction resets the node's SID.
func TestTxClearResetsSID(t *testing.T) {
	sid := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-500")
	n := NewNode(Name, "n", ObjectSid, NVSID(sid))
	g := testGraph(n)
	if n.SID() != sid {
		t.Fatal("SID not read")
	}
	tx := g.Begin("clear")
	tx.Node(n).Clear(ObjectSid)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if !n.SID().IsBlank() {
		t.Error("SID still cached after objectSid was cleared")
	}
}
