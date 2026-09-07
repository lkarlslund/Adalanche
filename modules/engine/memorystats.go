package engine

import (
	"sync/atomic"
	"time"
	"unsafe"
)

// MemoryStatistics contains aggregate counts, never object identifiers or data.
// Byte estimates exclude allocator/map overhead and shared string backing stores.
// They are not a total heap measurement and must not be subtracted from RSS.
type MemoryStatistics struct {
	CapturedAt            time.Time `json:"captured_at"`
	Nodes                 uint64    `json:"nodes"`
	AttributeKeys         uint64    `json:"attribute_keys"`
	AttributeValues       uint64    `json:"attribute_values"`
	AttributeSlotsBytes   uint64    `json:"estimated_attribute_value_slice_capacity_bytes"`
	ChildSlotsBytes       uint64    `json:"estimated_child_slice_capacity_bytes"`
	DescriptorReferences  uint64    `json:"descriptor_references"`
	CachedDescriptors     uint64    `json:"cached_descriptors"`
	CachedACEs            uint64    `json:"cached_aces"`
	AdjacencyEntries      uint64    `json:"adjacency_entries_both_directions"`
	EdgeCombinations      uint64    `json:"edge_combinations"`
	IndexKeys             uint64    `json:"index_keys"`
	IndexReferences       uint64    `json:"index_references"`
	NodeStructBytes       uint64    `json:"estimated_node_struct_bytes"`
	NodeSlotsBytes        uint64    `json:"estimated_node_slice_capacity_bytes"`
	AdjacencyPayloadBytes uint64    `json:"adjacency_logical_payload_bytes"`
	CombinationSliceBytes uint64    `json:"estimated_combination_slice_capacity_bytes"`
	DescriptorStructBytes uint64    `json:"estimated_cached_descriptor_struct_bytes"`
	ACESliceBytes         uint64    `json:"estimated_cached_ace_slice_capacity_bytes"`
	IndexSlotsBytes       uint64    `json:"estimated_index_node_slice_capacity_bytes"`
	Notes                 string    `json:"notes"`
}

var memoryStatisticsEnabled atomic.Bool
var latestMemoryStatistics atomic.Pointer[MemoryStatistics]

func EnableMemoryStatistics(enabled bool) {
	memoryStatisticsEnabled.Store(enabled)
	latestMemoryStatistics.Store(nil)
}

// LatestMemoryStatistics returns a small value copy from the last finalized graph.
func LatestMemoryStatistics() *MemoryStatistics {
	if s := latestMemoryStatistics.Load(); s != nil {
		copy := *s
		return &copy
	}
	return nil
}

func captureMemoryStatistics(g *IndexedGraph) {
	if memoryStatisticsEnabled.Load() {
		s := g.EstimateMemory()
		latestMemoryStatistics.Store(&s)
	}
}

// EstimateMemory requires a quiescent graph, as do graph finalizers. It uses
// constant additional working space; no graph copy or per-object tracking set.
func (g *IndexedGraph) EstimateMemory() MemoryStatistics {
	s := MemoryStatistics{CapturedAt: time.Now().UTC(), Notes: "Graph counts are from finalization; descriptor cache is process-wide. Adjacency counts include both directions. Estimates omit map buckets, allocator overhead, attribute payloads, strings, temporary graphs, and extension/report state; categories are not an exhaustive heap total."}
	s.Nodes = uint64(len(g.nodes))
	s.NodeStructBytes = s.Nodes * uint64(unsafe.Sizeof(Node{}))
	s.NodeSlotsBytes = uint64(cap(g.nodes)) * uint64(unsafe.Sizeof((*Node)(nil)))
	for _, n := range g.nodes {
		s.AttributeKeys += uint64(len(n.values.attributes))
		s.AttributeValues += uint64(len(n.values.values))
		s.AttributeSlotsBytes += uint64(cap(n.values.values)) * uint64(unsafe.Sizeof(AttributeValue(nil)))
		s.ChildSlotsBytes += uint64(cap(n.children.nodes)) * uint64(unsafe.Sizeof((*Node)(nil)))
		if n.sdcache != nil {
			s.DescriptorReferences++
		}
	}
	for _, direction := range g.edges {
		for _, targets := range direction {
			s.AdjacencyEntries += uint64(len(targets))
		}
	}
	s.AdjacencyPayloadBytes = s.AdjacencyEntries * uint64(unsafe.Sizeof(NodeIndex(0))+unsafe.Sizeof(EdgeCombo(0)))
	s.EdgeCombinations = uint64(len(g.edgeCombos))
	s.CombinationSliceBytes = uint64(cap(g.edgeCombos)) * uint64(unsafe.Sizeof(EdgeBitmap{}))
	addIndex := func(nodes *NodeSlice) {
		s.IndexKeys++
		s.IndexReferences += uint64(len(nodes.nodes))
		s.IndexSlotsBytes += uint64(cap(nodes.nodes)) * uint64(unsafe.Sizeof((*Node)(nil)))
	}
	for _, index := range g.indexes {
		if index != nil {
			for _, nodes := range index.lookup {
				addIndex(nodes)
			}
		}
	}
	for _, index := range g.multiindexes {
		if index != nil {
			for _, nodes := range index.lookup {
				addIndex(nodes)
			}
		}
	}
	securityDescriptorCache.Range(func(_ string, sd *SecurityDescriptor) bool {
		s.CachedDescriptors++
		s.CachedACEs += uint64(len(sd.DACL.Entries) + len(sd.SACL.Entries))
		s.DescriptorStructBytes += uint64(unsafe.Sizeof(SecurityDescriptor{}))
		s.ACESliceBytes += uint64(cap(sd.DACL.Entries)+cap(sd.SACL.Entries)) * uint64(unsafe.Sizeof(ACE{}))
		return true
	})
	return s
}
