package engine

import "testing"

func TestMemoryStatisticsSharedDescriptors(t *testing.T) {
	const key = "synthetic-memory-statistics-descriptor"
	before := NewIndexedGraph().EstimateMemory()
	sd := &SecurityDescriptor{DACL: ACL{Entries: make([]ACE, 2, 4)}}
	securityDescriptorCache.Store(key, sd)
	t.Cleanup(func() { securityDescriptorCache.Delete(key) })
	g := NewIndexedGraph()
	a, b := NewNode(Name, "synthetic-a"), NewNode(Name, "synthetic-b")
	a.sdcache, b.sdcache = sd, sd
	g.Add(a)
	g.Add(b)
	g.EdgeTo(a, b, testEdge("memory-statistics"))
	s := g.EstimateMemory()
	if s.Nodes != 2 || s.DescriptorReferences != 2 || s.CachedDescriptors != before.CachedDescriptors+1 || s.CachedACEs != before.CachedACEs+2 {
		t.Fatalf("unexpected aggregate counts: %+v", s)
	}
	if s.AdjacencyEntries != 2 || s.AdjacencyPayloadBytes != 12 || s.ACESliceBytes <= before.ACESliceBytes || s.AttributeValues == 0 {
		t.Fatalf("unexpected storage estimates: %+v", s)
	}
	latestMemoryStatistics.Store(&s)
	t.Cleanup(func() { latestMemoryStatistics.Store(nil) })
	copy := LatestMemoryStatistics()
	copy.Nodes = 0
	if LatestMemoryStatistics().Nodes != 2 {
		t.Fatal("caller mutated published statistics")
	}
}

func BenchmarkMemoryStatistics(b *testing.B) {
	g := NewIndexedGraph()
	for range 10000 {
		g.Add(NewNode())
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = g.EstimateMemory()
	}
}
