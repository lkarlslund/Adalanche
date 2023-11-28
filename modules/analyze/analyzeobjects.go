package analyze

import (
	"sort"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/graph"
	"github.com/lkarlslund/adalanche/modules/query"
	"github.com/lkarlslund/adalanche/modules/ui"
)

var SortBy engine.Attribute = engine.NonExistingAttribute

var EdgeMemberOfGroup = engine.NewEdge("MemberOfGroup") // Get rid of this

func NewAnalyzeObjectsOptions() AnalyzeObjectsOptions {
	return AnalyzeObjectsOptions{
		MethodsF:                  engine.AllEdgesBitmap,
		MethodsM:                  engine.AllEdgesBitmap,
		MethodsL:                  engine.AllEdgesBitmap,
		Direction:                 engine.In,
		MaxDepth:                  -1,
		MaxOutgoingConnections:    -1,
		MinEdgeProbability:        0,
		MinAccumulatedProbability: 0,
		PruneIslands:              false,
	}
}

type AnalyzeObjectsOptions struct {
	Objects                   *engine.Objects
	StartFilter               query.NodeFilter
	MiddleFilter              query.NodeFilter
	EndFilter                 query.NodeFilter
	ObjectTypesF              []engine.ObjectType
	ObjectTypesM              []engine.ObjectType
	ObjectTypesL              []engine.ObjectType
	MethodsL                  engine.EdgeBitmap
	MethodsM                  engine.EdgeBitmap
	MethodsF                  engine.EdgeBitmap
	MaxDepth                  int
	MaxOutgoingConnections    int
	Direction                 engine.EdgeDirection
	Backlinks                 bool // Full backlinks
	Fuzzlevel                 int  // Backlink depth
	MinEdgeProbability        engine.Probability
	MinAccumulatedProbability engine.Probability
	PruneIslands              bool
	NodeLimit                 int
}

type GraphNode struct {
	CanExpand              int
	roundadded             int
	accumulatedprobability float32 // 0-1
}

type PostProcessorFunc func(pg graph.Graph[*engine.Object, engine.EdgeBitmap]) graph.Graph[*engine.Object, engine.EdgeBitmap]

var PostProcessors []PostProcessorFunc

// type AnalysisNode struct {
// 	*engine.Object
// 	engine.DynamicFields
// }

type AnalysisResults struct {
	Graph   graph.Graph[*engine.Object, engine.EdgeBitmap]
	Removed int
}

func AnalyzeObjects(opts AnalyzeObjectsOptions) AnalysisResults {
	if opts.MethodsM.Count() == 0 {
		opts.MethodsM = opts.MethodsF
	}
	if opts.MethodsL.Count() == 0 {
		opts.MethodsL = opts.MethodsM
	}

	if len(opts.ObjectTypesM) == 0 {
		opts.ObjectTypesM = opts.ObjectTypesF
	}
	if len(opts.ObjectTypesL) == 0 {
		opts.ObjectTypesL = opts.ObjectTypesM
	}

	pg := graph.NewGraph[*engine.Object, engine.EdgeBitmap]()
	extrainfo := make(map[*engine.Object]*GraphNode)

	// Convert to our working graph
	processinground := 1
	query.Execute(opts.StartFilter, opts.Objects).Iterate(func(o *engine.Object) bool {
		pg.Set(o, "target", true)

		for o := range pg.Nodes() {
			if ei, found := extrainfo[o]; !found || ei.roundadded == 0 {
				extrainfo[o] = (&GraphNode{
					roundadded:             processinground,
					accumulatedprobability: 1,
				})
			}
		}

		return true
	})

	// Methods and ObjectTypes allowed
	detectedges := opts.MethodsF

	var detectobjecttypes map[engine.ObjectType]struct{}
	// If there are any, put them in a map - otherwise it's faster NOT to filter by checking if the filter map is nil
	if len(opts.ObjectTypesF) > 0 {
		detectobjecttypes = make(map[engine.ObjectType]struct{})
		for _, ot := range opts.ObjectTypesF {
			detectobjecttypes[ot] = struct{}{}
		}
	}

	pb := ui.ProgressBar("Analyzing graph", opts.MaxDepth)
	for opts.MaxDepth >= processinground || opts.MaxDepth == -1 {
		pb.Add(1)
		if processinground == 2 {
			detectedges = opts.MethodsM
			detectobjecttypes = nil
			if len(opts.ObjectTypesM) > 0 {
				detectobjecttypes = make(map[engine.ObjectType]struct{})
				for _, ot := range opts.ObjectTypesM {
					detectobjecttypes[ot] = struct{}{}
				}
			}
		}

		ui.Debug().Msgf("Processing round %v with %v total objects and %v connections", processinground, pg.Order(), pg.Size())

		nodesatstartofround := pg.Order()

		for currentobject := range pg.Nodes() {
			// All nodes need to be processed in the next round
			ei := extrainfo[currentobject]

			if ei == nil /* just added */ || ei.roundadded != processinground /* already processed */ {
				continue
			}

			newconnectionsmap := make(map[graph.NodePair[*engine.Object]]engine.EdgeBitmap) // Pwn Connection between objects

			// Iterate over ever edges
			currentobject.Edges(opts.Direction).Range(func(nextobject *engine.Object, eb engine.EdgeBitmap) bool {
				// If this is not a chosen edge, skip it
				detectededges := eb.Intersect(detectedges)

				if detectededges.IsBlank() {
					// Nothing useful or just a deny ACL, skip it
					return true // continue
				}

				if detectobjecttypes != nil {
					if _, found := detectobjecttypes[nextobject.Type()]; !found {
						// We're filtering on types, and it's not wanted
						return true //continue
					}
				}

				// Edge probability
				var maxprobability engine.Probability
				if opts.Direction == engine.In {
					maxprobability = detectededges.MaxProbability(nextobject, currentobject)
				} else {
					maxprobability = detectededges.MaxProbability(currentobject, nextobject)
				}
				if maxprobability < engine.Probability(opts.MinEdgeProbability) {
					// Too unlikeliy, so we skip it
					return true // continue
				}

				// Accumulated node probability
				accumulatedprobability := ei.accumulatedprobability * float32(maxprobability) / 100
				if accumulatedprobability < float32(opts.MinAccumulatedProbability)/100 {
					// Too unlikeliy, so we skip it
					return true // continue
				}

				// If we allow backlinks, all pwns are mapped, no matter who is the victim
				// Targets are allowed to pwn each other as a way to reach the goal of pwning all of them
				// If pwner is already processed, we don't care what it can pwn someone more far away from targets
				// If pwner is our attacker, we always want to know what it can do
				found := pg.HasNode(nextobject) // It could JUST have been added to the graph by another node in current processing round though

				// SKIP THIS IF
				if
				// We're not including backlinks
				!opts.Backlinks &&
					// It's found
					found &&
					// This is not the first round
					processinground > 1 &&
					// It was found in an earlier round
					extrainfo[nextobject] != nil && extrainfo[nextobject].roundadded+opts.Fuzzlevel <= processinground &&
					// If SIDs match between objects, it's a cross forest/domain link and we want to see it
					(currentobject.SID().IsNull() || nextobject.SID().IsNull() || currentobject.SID().Component(2) != 21 || currentobject.SID() != nextobject.SID()) {
					// skip it
					return true // continue
				}

				if opts.MiddleFilter != nil && !opts.MiddleFilter.Evaluate(nextobject) {
					// skip unwanted middle objects
					return true // continue
				}

				if opts.Direction == engine.In {
					newconnectionsmap[graph.NodePair[*engine.Object]{
						Source: nextobject,
						Target: currentobject}] = detectededges
				} else {
					newconnectionsmap[graph.NodePair[*engine.Object]{
						Source: currentobject,
						Target: nextobject}] = detectededges
				}

				extrainfo[nextobject] = &GraphNode{
					roundadded:             processinground + 1,
					accumulatedprobability: ei.accumulatedprobability * float32(maxprobability) / 100,
				}

				return true
			})

			if opts.MaxOutgoingConnections == -1 || len(newconnectionsmap) < opts.MaxOutgoingConnections {
				for pwnpair, detectedmethods := range newconnectionsmap {
					pg.AddEdge(pwnpair.Source, pwnpair.Target, detectedmethods)
				}
				// Add pwn target to graph for processing
			} else {
				ui.Debug().Msgf("Outgoing expansion limit hit %v for object %v, there was %v connections", opts.MaxOutgoingConnections, currentobject.Label(), len(newconnectionsmap))
				var added int
				var groupcount int
				for _, detectedmethods := range newconnectionsmap {
					// We assume the number of groups are limited and add them anyway
					if detectedmethods.IsSet(EdgeMemberOfGroup) {
						groupcount++
					}
				}

				if groupcount < opts.MaxOutgoingConnections {
					// Add the groups, but not the rest
					for pwnpair, detectedmethods := range newconnectionsmap {
						// We assume the number of groups are limited and add them anyway
						if detectedmethods.IsSet(EdgeMemberOfGroup) {
							pg.AddEdge(pwnpair.Source, pwnpair.Target, detectedmethods)
							delete(newconnectionsmap, pwnpair)
							added++
						}
					}
					ui.Debug().Msgf("Expansion limit compromise - added %v groups as they fit under the expansion limit %v", added, opts.MaxOutgoingConnections)
				}

				// Add some more to expansion limit hit objects if we know how
				if SortBy != engine.NonExistingAttribute {
					var additionaladded int

					// Find the most important ones that are not groups
					var notadded []graph.GraphNodePairEdge[*engine.Object, engine.EdgeBitmap]
					for pwnpair, detectedmethods := range newconnectionsmap {
						notadded = append(notadded, graph.GraphNodePairEdge[*engine.Object, engine.EdgeBitmap]{
							Source: pwnpair.Source,
							Target: pwnpair.Target,
							Edge:   detectedmethods,
						})
					}

					if SortBy != engine.NonExistingAttribute {
						sort.Slice(notadded, func(i, j int) bool {
							if opts.Direction == engine.In {
								iv, _ := notadded[i].Source.AttrInt(SortBy)
								jv, _ := notadded[j].Source.AttrInt(SortBy)
								return iv > jv
							}
							iv, _ := notadded[i].Target.AttrInt(SortBy)
							jv, _ := notadded[j].Target.AttrInt(SortBy)
							return iv > jv
						})
					}

					// Add up to limit
					for i := 0; i+added < opts.MaxOutgoingConnections && i < len(notadded); i++ {
						pg.AddEdge(notadded[i].Source, notadded[i].Target, notadded[i].Edge)
						additionaladded++
					}

					ui.Debug().Msgf("Added additionally %v prioritized objects", additionaladded)
					added += additionaladded
				}

				ei.CanExpand = len(newconnectionsmap) - added
			}
		}
		ui.Debug().Msgf("Processing round %v yielded %v new objects", processinground, pg.Order()-nodesatstartofround)

		if nodesatstartofround == pg.Order() {
			// Nothing was added, we're done
			break
		}

		processinground++
	}
	pb.Finish()

	ui.Debug().Msgf("Analysis result total %v objects", pg.Order())

	if len(extrainfo) != pg.Order() {
		ui.Warn().Msgf("Not all nodes were processed. Expected %v, processed %v", pg.Order(), len(extrainfo))
	}

	pb = ui.ProgressBar("Removing filtered nodes", pg.Order())

	// Remove outer end nodes that are invalid
	detectobjecttypes = nil
	if len(opts.ObjectTypesL) > 0 {
		detectobjecttypes = make(map[engine.ObjectType]struct{})
		for _, ot := range opts.ObjectTypesL {
			detectobjecttypes[ot] = struct{}{}
		}
	}

	// Keep removing stuff while it makes sense
	for {
		var removed int

		// This map contains all the nodes that is pointed by someone else. If you're in this map you're not an outer node
		var outernodes []*engine.Object
		if opts.Direction == engine.In {
			outernodes = pg.StartingNodes()
		} else {
			outernodes = pg.EndingNodes()
		}
		outernodemap := make(map[*engine.Object]struct{})

		for _, outernode := range outernodes {
			outernodemap[outernode] = struct{}{}
		}

		for pair, endedge := range pg.Edges() {
			var endnode *engine.Object
			if opts.Direction == engine.In {
				endnode = pair.Source
			} else {
				endnode = pair.Target
			}
			if _, found := outernodemap[endnode]; found {
				// Outer node
				if opts.MethodsL.Intersect(endedge).Count() == 0 {
					// No matches on LastMethods
					pg.DeleteNode(endnode)
					pb.Add(1)
					removed++
					continue
				}
				if detectobjecttypes != nil {
					if _, found := detectobjecttypes[endnode.Type()]; !found {
						// No matches on LastMethods
						pg.DeleteNode(endnode)
						pb.Add(1)
						removed++
						continue
					}
				}
				if opts.EndFilter != nil && !opts.EndFilter.Evaluate(endnode) {
					// does it exist in the exclude last list
					pg.DeleteNode(endnode)
					pb.Add(1)
					removed++
					continue
				}
			}
		}

		if removed == 0 {
			break
		}

		ui.Debug().Msgf("Post graph object filtering processing round removed %v nodes", removed)
	}
	pb.Finish()

	ui.Debug().Msgf("After filtering we have %v objects", pg.Order())

	totalnodes := pg.Order()
	toomanynodes := pg.Order() - opts.NodeLimit
	if opts.NodeLimit > 0 && toomanynodes > 0 {
		// Prune nodes until we dont have too many
		lefttoremove := toomanynodes
		pb = ui.ProgressBar("Removing excessive nodes", lefttoremove)

		for lefttoremove > 0 {
			// This map contains all the nodes that point to someone else. If you're in this map you're not an outer node
			var removedthisround, maxround int

			pointedtobysomeone := make(map[*engine.Object]struct{})
			var outernodes []*engine.Object
			if opts.Direction == engine.In {
				outernodes = pg.StartingNodes()
			} else {
				outernodes = pg.EndingNodes()
			}
			for _, outernode := range outernodes {
				pointedtobysomeone[outernode] = struct{}{}
				if maxround < extrainfo[outernode].roundadded {
					maxround = extrainfo[outernode].roundadded
				}
			}

			for _, outernode := range outernodes {
				if extrainfo[outernode].roundadded == maxround {
					pg.DeleteNode(outernode)
					pb.Add(1)
					lefttoremove--
					removedthisround++
				}
				if lefttoremove == 0 {
					break
				}
			}
			if removedthisround == 0 && lefttoremove > 0 {
				ui.Warn().Msgf("Could not find any outer nodes to remove, still should remove %v nodes", lefttoremove)
				break
			}
		}
	}

	pb.Finish()

	// PruneIslands
	var prunedislands int
	if opts.PruneIslands {
		// Find island nodes
		for _, islandnode := range pg.Islands() {
			pg.DeleteNode(islandnode)
			prunedislands++
		}
	}
	if prunedislands > 0 {
		ui.Debug().Msgf("Pruning islands removed %v nodes", prunedislands)
		ui.Debug().Msgf("After pruning we have %v objects", pg.Order())

	}

	ui.Info().Msgf("Graph query resulted in %v nodes", pg.Order())

	pg.Nodes() // Trigger cleanup, important otherwise they get readded below
	for eo, ei := range extrainfo {
		if pg.HasNode(eo) && ei.CanExpand > 0 {
			pg.Set(eo, "canexpand", ei.CanExpand)
		}
	}

	ui.Debug().Msgf("Final analysis node count is %v objects", pg.Order())

	return AnalysisResults{
		Graph:   pg,
		Removed: totalnodes - pg.Order(),
	}
}
