package engine

import (
	"sort"

	"github.com/lkarlslund/adalanche/modules/ui"
)

var SortBy Attribute = NonExistingAttribute

var EdgeMemberOfGroup = NewEdge("MemberOfGroup") // Get rid of this

func NewAnalyzeObjectsOptions() AnalyzeObjectsOptions {
	return AnalyzeObjectsOptions{
		MethodsF:               AllEdgesBitmap,
		MethodsM:               AllEdgesBitmap,
		MethodsL:               AllEdgesBitmap,
		Reverse:                false,
		MaxDepth:               99,
		MaxOutgoingConnections: -1,
		MinProbability:         0,
		PruneIslands:           false,
	}
}

type AnalyzeObjectsOptions struct {
	IncludeObjects         *Objects
	ExcludeObjects         *Objects
	ObjectTypesF           []ObjectType
	ObjectTypesM           []ObjectType
	ObjectTypesL           []ObjectType
	MethodsL               EdgeBitmap
	MethodsM               EdgeBitmap
	MethodsF               EdgeBitmap
	MaxDepth               int
	MaxOutgoingConnections int
	Reverse                bool
	Backlinks              bool // Full backlinks
	Fuzzlevel              int  // Backlink depth
	MinProbability         Probability
	PruneIslands           bool
}

type PostProcessorFunc func(pg Graph) Graph

var PostProcessors []PostProcessorFunc

func AnalyzeObjects(opts AnalyzeObjectsOptions) (pg Graph) {
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

	type roundinfo struct {
		roundadded int
		processed  bool
		canexpand  int
	}

	connectionsmap := make(map[ObjectPair]EdgeBitmap)    // Pwn Connection between objects
	implicatedobjectsmap := make(map[*Object]*roundinfo) // Object -> Processed in round n

	// Direction to search, forward = who can pwn interestingobjects, !forward = who can interstingobjects pwn
	forward := !opts.Reverse

	// Convert to our working map
	processinground := 1
	opts.IncludeObjects.Iterate(func(o *Object) bool {
		implicatedobjectsmap[o] = &roundinfo{
			roundadded: processinground,
		}
		return true
	})

	// Methods and ObjectTypes allowed
	detectedges := opts.MethodsF

	var detectobjecttypes map[ObjectType]struct{}
	// If there are any, put them in a map - otherwise it's faster NOT to filter by checking if the filter map is nil
	if len(opts.ObjectTypesF) > 0 {
		detectobjecttypes = make(map[ObjectType]struct{})
		for _, ot := range opts.ObjectTypesF {
			detectobjecttypes[ot] = struct{}{}
		}
	}

	pb := ui.ProgressBar("Analyzing graph", opts.MaxDepth)
	for opts.MaxDepth >= processinground {
		pb.Add(1)
		if processinground == 2 {
			detectedges = opts.MethodsM
			detectobjecttypes = nil
			if len(opts.ObjectTypesM) > 0 {
				detectobjecttypes = make(map[ObjectType]struct{})
				for _, ot := range opts.ObjectTypesM {
					detectobjecttypes[ot] = struct{}{}
				}
			}
		}

		ui.Debug().Msgf("Processing round %v with %v total objects and %v connections", processinground, len(implicatedobjectsmap), len(connectionsmap))
		newimplicatedobjects := make(map[*Object]struct{})

		for object, ri := range implicatedobjectsmap {
			if ri.processed {
				continue
			}

			newconnectionsmap := make(map[ObjectPair]EdgeBitmap) // Pwn Connection between objects

			var ec EdgeDirection
			if forward {
				ec = In
			} else {
				ec = Out
			}

			// Iterate over ever outgoing pwn
			// This is not efficient, but we sort the pwnlist first
			object.Edges(ec).Range(func(target *Object, eb EdgeBitmap) bool {
				// If this is not a chosen method, skip it
				detectededges := eb.Intersect(detectedges)

				if detectededges.IsBlank() {
					// Nothing useful or just a deny ACL, skip it
					return true // continue
				}

				if detectobjecttypes != nil {
					if _, found := detectobjecttypes[target.Type()]; !found {
						// We're filtering on types, and it's not wanted
						return true //continue
					}
				}

				var maxprobability Probability
				if forward {
					maxprobability = detectededges.MaxProbability(target, object)
				} else {
					maxprobability = detectededges.MaxProbability(object, target)
				}
				if maxprobability < Probability(opts.MinProbability) {
					// Too unlikeliy, so we skip it
					return true // continue
				}

				// If we allow backlinks, all pwns are mapped, no matter who is the victim
				// Targets are allowed to pwn each other as a way to reach the goal of pwning all of them
				// If pwner is already processed, we don't care what it can pwn someone more far away from targets
				// If pwner is our attacker, we always want to know what it can do
				tri, found := implicatedobjectsmap[target]

				// SKIP THIS IF
				if
				// We're not including backlinks
				!opts.Backlinks &&
					// It's found
					found &&
					// This is not the first round
					processinground > 1 &&
					// It was found in an earlier round
					tri.roundadded+opts.Fuzzlevel <= processinground &&
					// If SIDs match between objects, it's a cross forest link and we want to see it
					(object.SID().IsNull() || target.SID().IsNull() || object.SID().Component(2) != 21 || object.SID() != target.SID()) {
					// skip it
					return true // continue
				}

				if opts.ExcludeObjects != nil {
					if _, found := opts.ExcludeObjects.FindID(target.ID()); found {
						// skip excluded objects
						// ui.Debug().Msgf("Excluding target %v", pwntarget.DN())
						return true // continue
					}
				}

				newconnectionsmap[ObjectPair{Source: object, Target: target}] = detectededges

				return true
			})

			if opts.MaxOutgoingConnections == -1 || len(newconnectionsmap) < opts.MaxOutgoingConnections {
				for pwnpair, detectedmethods := range newconnectionsmap {
					connectionsmap[pwnpair] = detectedmethods
					if _, found := implicatedobjectsmap[pwnpair.Target]; !found {
						newimplicatedobjects[pwnpair.Target] = struct{}{} // Add this to work map as non-processed
					}
				}
				// Add pwn target to graph for processing
			} else {
				ui.Debug().Msgf("Outgoing expansion limit hit %v for object %v, there was %v connections", opts.MaxOutgoingConnections, object.Label(), len(newconnectionsmap))
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
							connectionsmap[pwnpair] = detectedmethods
							if _, found := implicatedobjectsmap[pwnpair.Target]; !found {
								newimplicatedobjects[pwnpair.Target] = struct{}{} // Add this to work map as non-processed
							}
							added++
						}
					}
					ui.Debug().Msgf("Expansion limit compromise - added %v groups as they fit under the expansion limit %v", added, opts.MaxOutgoingConnections)
				}

				// Add some more to expansion limit hit objects if we know how
				if SortBy != NonExistingAttribute {
					var additionaladded int

					// Find the most important ones that are not groups
					var notadded []GraphEdge
					for pwnpair, detectedmethods := range newconnectionsmap {
						if _, found := implicatedobjectsmap[pwnpair.Target]; !found {
							notadded = append(notadded, GraphEdge{
								Source:     pwnpair.Source,
								Target:     pwnpair.Target,
								EdgeBitmap: detectedmethods,
							})
						}
					}

					sort.Slice(notadded, func(i, j int) bool {
						iv, _ := notadded[i].Target.AttrInt(SortBy)
						jv, _ := notadded[j].Target.AttrInt(SortBy)
						return iv > jv
					})

					for i := 0; i+added < opts.MaxOutgoingConnections && i < len(notadded); i++ {
						connectionsmap[ObjectPair{
							Source: notadded[i].Source,
							Target: notadded[i].Target,
						}] = notadded[i].EdgeBitmap
						if _, found := implicatedobjectsmap[notadded[i].Target]; !found {
							newimplicatedobjects[notadded[i].Target] = struct{}{} // Add this as our best item
						}
						additionaladded++
					}

					ui.Debug().Msgf("Added additionally %v prioritized objects", additionaladded)
					added += additionaladded
				}

				ri.canexpand = len(newconnectionsmap) - added
			}

			ri.processed = true
			// We're done processing this
		}
		ui.Debug().Msgf("Processing round %v yielded %v new objects", processinground, len(newimplicatedobjects))
		if len(newimplicatedobjects) == 0 {
			// Nothing more to do
			break
		}

		processinground++
		for newentry := range newimplicatedobjects {
			implicatedobjectsmap[newentry] = &roundinfo{
				roundadded: processinground,
			}
		}
	}
	pb.Finish()

	pb = ui.ProgressBar("Removing filtered nodes", len(connectionsmap))

	// Remove outer end nodes that are invalid
	detectobjecttypes = nil
	if len(opts.ObjectTypesL) > 0 {
		detectobjecttypes = make(map[ObjectType]struct{})
		for _, ot := range opts.ObjectTypesL {
			detectobjecttypes[ot] = struct{}{}
		}
	}

	var weremovedsomething bool
	for {
		var removed int

		// This map contains all the nodes that point to someone else. If you're in this map you're not an outer node
		pointsatsomeone := make(map[*Object]struct{})
		for pair := range connectionsmap {
			pointsatsomeone[pair.Source] = struct{}{}
		}

		for pair, detectedmethods := range connectionsmap {
			if _, found := pointsatsomeone[pair.Target]; !found {
				// Outer node
				if opts.MethodsL.Intersect(detectedmethods).Count() == 0 {
					// No matches on LastMethods
					delete(connectionsmap, pair)
					pb.Add(1)
					removed++
				} else if detectobjecttypes != nil {
					if _, found := detectobjecttypes[pair.Target.Type()]; !found {
						// No matches on LastMethods
						delete(connectionsmap, pair)
						pb.Add(1)
						removed++
					}
				}
			}
		}

		if removed == 0 {
			break
		}

		ui.Debug().Msgf("Post graph object filtering remove %v nodes", removed)

		weremovedsomething = true
	}
	pb.Finish()

	// PruneIslands
	var prunedislands int
	if opts.PruneIslands || weremovedsomething {
		// Find island nodes
		pointedto := make(map[*Object]struct{})
		for pair := range connectionsmap {
			pointedto[pair.Source] = struct{}{}
			pointedto[pair.Target] = struct{}{}
		}
		for node := range implicatedobjectsmap {
			if _, found := pointedto[node]; !found {
				if _, found := opts.IncludeObjects.FindID(node.ID()); opts.PruneIslands || !found {
					delete(implicatedobjectsmap, node)
					prunedislands++
				}
			}
		}
	}
	if prunedislands > 0 {
		ui.Debug().Msgf("Pruning islands removed %v nodes", prunedislands)
	}

	ui.Info().Msgf("Graph query resulted in %v nodes", len(implicatedobjectsmap))

	// Convert map to slice
	pg.Connections = make([]GraphEdge, len(connectionsmap))
	i := 0
	for connection, methods := range connectionsmap {
		nc := GraphEdge{
			Source:     connection.Source,
			Target:     connection.Target,
			EdgeBitmap: methods,
		}
		if forward {
			nc.Source, nc.Target = nc.Target, nc.Source // swap 'em to get arrows pointing correctly
		}
		pg.Connections[i] = nc
		i++
	}

	pg.Nodes = make([]GraphNode, len(implicatedobjectsmap))
	i = 0
	for object, ri := range implicatedobjectsmap {
		pg.Nodes[i].Object = object
		if _, found := opts.IncludeObjects.FindID(object.ID()); found {
			pg.Nodes[i].Target = true
		}
		pg.Nodes[i].CanExpand = ri.canexpand
		i++
	}

	return
}
