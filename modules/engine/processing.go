package engine

import (
	"slices"
	"sort"
	"sync"

	"github.com/lkarlslund/adalanche/modules/ui"
)

func getMergeAttributes() []Attribute {
	var mergeon []Attribute
	for attr := range attributeinfos {
		if Attribute(attr).HasFlag(Merge) {
			mergeon = append(mergeon, Attribute(attr))
		}
	}
	sort.Slice(mergeon, func(i, j int) bool {
		isuccess := attributeinfos[mergeon[i]].mergeSuccesses.Load()
		jsuccess := attributeinfos[mergeon[j]].mergeSuccesses.Load()
		return jsuccess < isuccess
	})
	return mergeon
}

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
		// Release the goroutine, so we can GC this
		g.BulkLoadEdges(false)

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
	superGraph.BulkLoadEdges(true)
	globalroot := NewNode(
		Name, NV("Adalanche root node"),
		Type, NV("Root"),
	)
	superGraph.SetRoot(globalroot)

	orphancontainer := NewNode(Name, NV("Orphans"))
	orphancontainer.ChildOf(globalroot)
	superGraph.Add(orphancontainer)

	type mergeinfo struct {
		graph *IndexedGraph
		node  *Node
	}

	var trymerge []mergeinfo
	mergedNodesMap := make(map[*Node]*Node)
	var mergeMutex sync.Mutex

	// Iterate over all the object collections
	ui.Info().Msgf("Scanning %v nodes for mergeability potential", totalNodes)
	pb := ui.ProgressBar("Scanning nodes to add directly", int64(totalNodes))
	for _, g := range graphs {
		// We're grabbing the index directly for faster processing here
		dnindex := superGraph.GetIndex(DistinguishedName)

		if mergeroot := g.Root(); mergeroot != nil {
			mergeroot.ChildOf(globalroot)
		}

		// Add all nodes and edges from other graphs into the global graph
		g.IterateParallel(func(node *Node) bool {
			pb.Add(1)

			// Just fast track melting nodes with same DN together, solves duplicate schema items etc.
			if val := node.OneAttr(DistinguishedName); val != nil {
				if samedn, found := dnindex.Lookup(val); found {
					mergeMutex.Lock()
					mergedNodesMap[node] = samedn.First()
					mergeMutex.Unlock()
					return true
				}
			}

			if !node.HasAttr(DataSource) {
				mergeMutex.Lock()
				trymerge = append(trymerge, mergeinfo{graph: g, node: node})
				mergeMutex.Unlock()
			} else {
				// Just add it now
				superGraph.Add(node)
			}
			return true
		}, 0)
	}
	pb.Finish()

	// We now have a list of nodes that potentially can be merged into the global graph
	pb = ui.ProgressBar("Attempting merge on potential nodes", int64(len(trymerge)))
	conflictAttrs := getConflictAttributes()
	mergeAttrs := getMergeAttributes()
	for i, mergeinfo := range trymerge {
		pb.Add(1)
		node := mergeinfo.node
		// graph := mergeinfo.graph

		if i%16384 == 0 {
			// Refresh the list of attributes, ordered by most successfull first
			mergeAttrs = getMergeAttributes()
		}

		mergedTo, merged := superGraph.Merge(mergeAttrs, conflictAttrs, node)
		if merged {
			mergedNodesMap[node] = mergedTo
		} else {
			superGraph.Add(node)
		}
	}
	pb.Finish()

	aftermergetotalobjects := superGraph.Order()
	ui.Info().Msgf("After merge we have %v objects in the metaverse (merge eliminated %v objects)", aftermergetotalobjects, len(mergedNodesMap))

	// Add all outgoing edges from the other graphs
	pb = ui.ProgressBar("Adding edges", int64(totalEdges))
	for _, g := range graphs {
		g.IterateParallel(func(source *Node) bool {
			g.Edges(source, Out).Iterate(func(target *Node, ebm EdgeBitmap) bool {
				pb.Add(1)
				if newSource, merged := mergedNodesMap[source]; merged {
					source = newSource
				}
				if newTarget, merged := mergedNodesMap[target]; merged {
					target = newTarget
				}
				superGraph.SetEdge(source, target, ebm, true)
				return true
			})
			return true
		}, 0)
	}
	pb.Finish()
	superGraph.FlushEdges()

	var orphans int
	processed := make(map[*Node]struct{})
	var processobject func(o *Node)
	processobject = func(o *Node) {
		if _, done := processed[o]; !done {
			if !superGraph.Contains(o) {
				ui.Debug().Msgf("Child object %v wasn't added to index, fixed", o.Label())
				superGraph.Add(o)
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
			object.ChildOf(orphancontainer)
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
