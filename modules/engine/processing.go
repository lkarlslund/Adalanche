package engine

import (
	"slices"
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/ui"
)

func getConflictAttributes() []Attribute {
	var conflicts []Attribute
	for attr := range attributeinfos {
		if Attribute(attr).HasFlag(Single) && !Attribute(attr).HasFlag(DropWhenMerging) {
			conflicts = append(conflicts, Attribute(attr))
		}
	}
	return conflicts
}

func MergeGraphs(graphs []*IndexedGraph) (*IndexedGraph, error) {
	var largestGraph, largestGraphNodeCount, largestGraphEdgeCount, totalNodes, totalEdges int
	for i, g := range graphs {
		thisGraphNodeCount := g.Order()
		totalNodes += thisGraphNodeCount
		thisGraphEdgeCount := g.Size()
		totalEdges += thisGraphEdgeCount
		if thisGraphNodeCount > largestGraphNodeCount {
			largestGraph = i
			largestGraphNodeCount = thisGraphNodeCount
			largestGraphEdgeCount = thisGraphEdgeCount
		}
	}
	_ = largestGraph
	_ = largestGraphEdgeCount
	otherNodes := totalNodes - largestGraphNodeCount
	_ = otherNodes

	// Largest graphs first
	slices.SortFunc(graphs, func(i, j *IndexedGraph) int {
		return j.Order() - i.Order()
	})

	ui.Info().Msgf("Initiating merge with a total of %v objects", totalNodes)

	// ui.Info().Msgf("Using object collection with %v objects as target to merge into .... reindexing it", len(globalobjects.Slice()))

	// Find all the attributes that can be merged objects on
	superGraph := NewIndexedGraph()
	globalroot := NewNode(
		Name, NV("Adalanche root node"),
		Type, NV("Root"),
	)
	superGraph.setRoot(globalroot)

	orphancontainer := NewNode(Name, NV("Orphans"))
	orphancontainer.childOf(globalroot)
	superGraph.add(orphancontainer)

	type mergeinfo struct {
		graph *IndexedGraph
		node  *Node
	}

	var trymerge []mergeinfo
	var sidStubs []*Node
	mergedNodesMap := make(map[*Node]*Node)
	var mergeMutex sync.Mutex

	// Iterate over all the object collections
	ui.Info().Msgf("Scanning %v nodes for mergeability potential", totalNodes)
	pb := ui.ProgressBar("Scanning nodes to add directly", int64(totalNodes))
	for _, g := range graphs {
		// We're grabbing the index directly for faster processing here
		dnindex := superGraph.GetIndex(DistinguishedName)

		if mergeroot := g.Root(); mergeroot != nil {
			mergeroot.childOf(globalroot)
		}

		// Add all nodes and edges from other graphs into the global graph
		g.IterateParallel(func(node *Node) bool {
			pb.Add(1)

			// Just fast track melting nodes with same DN together, solves duplicate schema items etc.
			if val := node.OneAttr(DistinguishedName); !val.IsNil() {
				if samedn, found := dnindex.Lookup(val); found {
					mergeMutex.Lock()
					mergedNodesMap[node] = samedn.First()
					mergeMutex.Unlock()
					return true
				}
			}

			if isDomainSIDStub(node) {
				mergeMutex.Lock()
				sidStubs = append(sidStubs, node)
				mergeMutex.Unlock()
			} else if !node.HasAttr(DataSource) {
				mergeMutex.Lock()
				trymerge = append(trymerge, mergeinfo{graph: g, node: node})
				mergeMutex.Unlock()
			} else {
				// Just add it now
				superGraph.add(node)
			}
			return true
		}, 0)
	}
	pb.Finish()

	// Nodes without a data source of their own are references to real
	// nodes; resolve them now that every real node is in place.
	references := make([]*Node, len(trymerge))
	for i, mi := range trymerge {
		references[i] = mi.node
	}
	resolveReferences(superGraph, references, mergedNodesMap)

	mergeSIDStubs(superGraph, sidStubs, mergedNodesMap)

	aftermergetotalobjects := superGraph.Order()
	ui.Info().Msgf("After merge we have %v objects in the metaverse (merge eliminated %v objects)", aftermergetotalobjects, len(mergedNodesMap))

	// Add all outgoing edges from the other graphs
	pb = ui.ProgressBar("Adding edges", int64(totalEdges))
	importer := NewEdgeImporter(totalEdges)
	for _, g := range graphs {
		g.IterateParallelStable(func(source *Node) bool {
			g.Edges(source, Out).Iterate(func(target *Node, ebm EdgeBitmap) bool {
				pb.Add(1)
				if newSource, merged := mergedNodesMap[source]; merged {
					source = newSource
				}
				if newTarget, merged := mergedNodesMap[target]; merged {
					target = newTarget
				}
				importer.Set(source, target, ebm, true)
				return true
			})
			return true
		}, 0)
	}
	pb.Finish()
	importer.Commit(superGraph)

	var orphans int
	processed := make(map[*Node]struct{})
	var processobject func(o *Node)
	processobject = func(o *Node) {
		if _, done := processed[o]; !done {
			if !superGraph.Contains(o) {
				ui.Debug().Msgf("Child object %v wasn't added to index, fixed", o.Label())
				superGraph.add(o)
			}
			processed[o] = struct{}{}
			o.Children().Iterate(func(child *Node) bool {
				processobject(child)
				return true
			})
		}
	}
	superGraph.Iterate(func(object *Node) bool {
		if object.Parent() == nil {
			object.childOf(orphancontainer)
			orphans++
		}
		processobject(object)
		return true
	})
	if orphans > 0 {
		ui.Warn().Msgf("Detected %v orphan objects in final results", orphans)
	}

	return superGraph, nil
}

// isDomainSIDStub reports whether a node only stands for a domain or
// machine account SID that a graph referred to without having the account:
// it has a domain-style SID but no distinguished name or data source.
func isDomainSIDStub(n *Node) bool {
	sid := n.SID()
	return !sid.IsBlank() && sid.Component(2) == 21 && sid.Component(3) != 0 &&
		!n.HasAttr(DistinguishedName) && !n.HasAttr(DataSource) && n.Children().Len() == 0
}

// mergeSIDStubs merges the stubs for each SID into the one real node with
// that SID. A domain account SID is unique across domains and forests, so
// every graph that referred to the account meant this node. When there is
// no such node, or several (machines cloned with the same machine SID), the
// stubs merge into one stub that stands for the SID.
func mergeSIDStubs(superGraph *IndexedGraph, stubs []*Node, mergedNodesMap map[*Node]*Node) {
	slices.SortStableFunc(stubs, func(a, b *Node) int { return strings.Compare(string(a.SID()), string(b.SID())) })
	for start := 0; start < len(stubs); {
		end := start + 1
		for end < len(stubs) && stubs[end].SID() == stubs[start].SID() {
			end++
		}
		group := stubs[start:end]
		start = end

		if real, found := superGraph.FindMulti(ObjectSid, NV(group[0].SID())); found && real.Len() == 1 {
			// The stubs carry nothing the real node lacks, so only their
			// edges move over.
			for _, stub := range group {
				mergedNodesMap[stub] = real.First()
			}
			continue
		}
		target := group[0]
		for _, stub := range group[1:] {
			target.absorb(stub)
			mergedNodesMap[stub] = target
		}
		superGraph.add(target)
	}
}
