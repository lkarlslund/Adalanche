package engine

import (
	"sort"

	"github.com/rs/zerolog/log"
)

var PwnMemberOfGroup = NewPwn("MemberOfGroup") // FIXME, this should be generalized to expand-anyway-priority somehoe

var SortBy Attribute

type ProbabilityCalculatorFunction func(source, target *Object) Probability

func (pm PwnMethod) RegisterProbabilityCalculator(doCalc ProbabilityCalculatorFunction) PwnMethod {
	pwnnums[pm].probability = doCalc
	return pm
}

func (pm PwnMethod) Describe(description string) PwnMethod {
	pwnnums[pm].Description = description
	return pm
}

func (pm PwnMethod) Probability(source, target *Object) Probability {
	if f := pwnnums[pm].probability; f != nil {
		return f(source, target)
	}

	// default
	return 100
}

func NewAnalyzeObjectsOptions() AnalyzeObjectsOptions {
	return AnalyzeObjectsOptions{
		MethodsF:               AllPwnMethods,
		MethodsM:               AllPwnMethods,
		MethodsL:               AllPwnMethods,
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
	MethodsL               PwnMethodBitmap
	MethodsM               PwnMethodBitmap
	MethodsF               PwnMethodBitmap
	MaxDepth               int
	MaxOutgoingConnections int
	Reverse                bool
	Backlinks              bool // Full backlinks
	Fuzzlevel              int  // Backlink depth
	MinProbability         Probability
	PruneIslands           bool
}

type PostProcessorFunc func(pg PwnGraph) PwnGraph

var PostProcessors []PostProcessorFunc

func AnalyzeObjects(opts AnalyzeObjectsOptions) (pg PwnGraph) {
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

	connectionsmap := make(map[PwnPair]PwnMethodBitmap)  // Pwn Connection between objects
	implicatedobjectsmap := make(map[*Object]*roundinfo) // Object -> Processed in round n

	// Direction to search, forward = who can pwn interestingobjects, !forward = who can interstingobjects pwn
	forward := !opts.Reverse

	// Convert to our working map
	processinground := 1
	for _, object := range opts.IncludeObjects.Slice() {
		implicatedobjectsmap[object] = &roundinfo{
			roundadded: processinground,
		}
	}

	// Methods and ObjectTypes allowed
	detectmethods := opts.MethodsF

	var detectobjecttypes map[ObjectType]struct{}
	// If there are any, put them in a map - otherwise it's faster NOT to filter by checking if the filter map is nil
	if len(opts.ObjectTypesF) > 0 {
		detectobjecttypes = make(map[ObjectType]struct{})
		for _, ot := range opts.ObjectTypesF {
			detectobjecttypes[ot] = struct{}{}
		}
	}

	for opts.MaxDepth >= processinground {
		if processinground == 2 {
			detectmethods = opts.MethodsM
			detectobjecttypes = nil
			if len(opts.ObjectTypesM) > 0 {
				detectobjecttypes = make(map[ObjectType]struct{})
				for _, ot := range opts.ObjectTypesM {
					detectobjecttypes[ot] = struct{}{}
				}
			}
		}

		log.Debug().Msgf("Processing round %v with %v total objects and %v connections", processinground, len(implicatedobjectsmap), len(connectionsmap))
		newimplicatedobjects := make(map[*Object]struct{})

		for object, ri := range implicatedobjectsmap {
			if ri.processed {
				continue
			}

			newconnectionsmap := make(map[PwnPair]PwnMethodBitmap) // Pwn Connection between objects

			var pwnlist PwnConnections
			if forward {
				pwnlist = object.PwnableBy
			} else {
				pwnlist = object.CanPwn
			}

			// Iterate over ever outgoing pwn
			// This is not efficient, but we sort the pwnlist first
			for _, pwntarget := range pwnlist.Objects() {
				pwninfo := pwnlist[pwntarget]

				// If this is not a chosen method, skip it
				detectedmethods := pwninfo.Intersect(detectmethods)

				methodcount := detectedmethods.Count()
				if methodcount == 0 {
					// Nothing useful or just a deny ACL, skip it
					continue
				}

				if detectobjecttypes != nil {
					if _, found := detectobjecttypes[pwntarget.Type()]; !found {
						// We're filtering on types, and it's not wanted
						continue
					}
				}

				var maxprobability Probability
				if forward {
					maxprobability = detectedmethods.MaxProbability(pwntarget, object)
				} else {
					maxprobability = detectedmethods.MaxProbability(object, pwntarget)
				}
				if maxprobability < Probability(opts.MinProbability) {
					// Too unlikeliy, so we skip it
					continue
				}

				// If we allow backlinks, all pwns are mapped, no matter who is the victim
				// Targets are allowed to pwn each other as a way to reach the goal of pwning all of them
				// If pwner is already processed, we don't care what it can pwn someone more far away from targets
				// If pwner is our attacker, we always want to know what it can do
				tri, found := implicatedobjectsmap[pwntarget]

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
					(object.SID().IsNull() || pwntarget.SID().IsNull() || object.SID().Component(2) != 21 || object.SID() != pwntarget.SID()) {
					// skip it
					continue
				}

				if opts.ExcludeObjects != nil {
					if _, found := opts.ExcludeObjects.FindByID(pwntarget.ID()); found {
						// skip excluded objects
						// log.Debug().Msgf("Excluding target %v", pwntarget.DN())
						continue
					}
				}

				newconnectionsmap[PwnPair{Source: object, Target: pwntarget}] = detectedmethods
			}

			if opts.MaxOutgoingConnections == -1 || len(newconnectionsmap) < opts.MaxOutgoingConnections {
				for pwnpair, detectedmethods := range newconnectionsmap {
					connectionsmap[pwnpair] = detectedmethods
					if _, found := implicatedobjectsmap[pwnpair.Target]; !found {
						newimplicatedobjects[pwnpair.Target] = struct{}{} // Add this to work map as non-processed
					}
				}
				// Add pwn target to graph for processing
			} else {
				log.Debug().Msgf("Outgoing expansion limit hit %v for object %v, there was %v connections", opts.MaxOutgoingConnections, object.Label(), len(newconnectionsmap))
				var added int
				var groupcount int
				for _, detectedmethods := range newconnectionsmap {
					// We assume the number of groups are limited and add them anyway
					if detectedmethods.IsSet(PwnMemberOfGroup) {
						groupcount++
					}
				}

				if groupcount < opts.MaxOutgoingConnections {
					// Add the groups, but not the rest
					for pwnpair, detectedmethods := range newconnectionsmap {
						// We assume the number of groups are limited and add them anyway
						if detectedmethods.IsSet(PwnMemberOfGroup) {
							connectionsmap[pwnpair] = detectedmethods
							if _, found := implicatedobjectsmap[pwnpair.Target]; !found {
								newimplicatedobjects[pwnpair.Target] = struct{}{} // Add this to work map as non-processed
							}
							added++
						}
					}
					log.Debug().Msgf("Expansion limit compromise - added %v groups as they fit under the expansion limit %v", added, opts.MaxOutgoingConnections)

					// Add some more to expansion limit hit objects if we know how
					if SortBy != 0 {

						// Find the most important ones that are not groups
						var notadded []PwnPair
						for pwnpair, _ := range newconnectionsmap {
							if _, found := implicatedobjectsmap[pwnpair.Target]; !found {
								notadded = append(notadded, pwnpair)
							}
						}

						sort.Slice(notadded, func(i, j int) bool {
							iv, _ := notadded[i].Target.AttrInt(SortBy)
							jv, _ := notadded[j].Target.AttrInt(SortBy)
							return iv > jv
						})

						for i := 0; i+added < opts.MaxOutgoingConnections; i++ {
							newimplicatedobjects[notadded[i].Target] = struct{}{} // Add this as our best item
						}
					}

					ri.canexpand = len(newconnectionsmap) - added
				}

			}

			ri.processed = true
			// We're done processing this
		}
		log.Debug().Msgf("Processing round %v yielded %v new objects", processinground, len(newimplicatedobjects))
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
					removed++
				} else if detectobjecttypes != nil {
					if _, found := detectobjecttypes[pair.Target.Type()]; !found {
						// No matches on LastMethods
						delete(connectionsmap, pair)
						removed++
					}
				}
			}
		}

		if removed == 0 {
			break
		}

		weremovedsomething = true
	}

	// PruneIslands
	if opts.PruneIslands || weremovedsomething {
		// Find island nodes
		pointedto := make(map[*Object]struct{})
		for pair := range connectionsmap {
			pointedto[pair.Source] = struct{}{}
			pointedto[pair.Target] = struct{}{}
		}
		for node := range implicatedobjectsmap {
			if _, found := pointedto[node]; !found {
				if _, found := opts.IncludeObjects.FindByID(node.ID()); opts.PruneIslands || !found {
					delete(implicatedobjectsmap, node)
				}
			}
		}
	}

	// Convert map to slice
	pg.Connections = make([]Edge, len(connectionsmap))
	i := 0
	for connection, methods := range connectionsmap {
		nc := Edge{
			Source:          connection.Source,
			Target:          connection.Target,
			PwnMethodBitmap: methods,
		}
		if forward {
			nc.Source, nc.Target = nc.Target, nc.Source // swap 'em to get arrows pointing correctly
		}
		pg.Connections[i] = nc
		i++
	}

	pg.Nodes = make([]Node, len(implicatedobjectsmap))
	i = 0
	for object, ri := range implicatedobjectsmap {
		pg.Nodes[i].Object = object
		if _, found := opts.IncludeObjects.FindByID(object.ID()); found {
			pg.Nodes[i].Target = true
		}
		pg.Nodes[i].CanExpand = ri.canexpand
		i++
	}

	return
}
