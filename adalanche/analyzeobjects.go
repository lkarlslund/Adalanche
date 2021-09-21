package main

import (
	"strings"

	"github.com/rs/zerolog/log"
)

type GraphObject struct {
	*Object
	Target    bool
	CanExpand int
}

type PwnGraph struct {
	Nodes       []GraphObject
	Connections []PwnConnection // Connection to Methods map
}

type PwnPair struct {
	Source, Target *Object
}

type PwnConnection struct {
	Source, Target *Object
	PwnMethodBitmap
}

func CalculateProbability(source, target *Object, method PwnMethod) Probability {
	switch method {
	case PwnACLContainsDeny:
		return 0
	case PwnLocalRDPRights:
		return 30
	case PwnLocalDCOMRights:
		return 50
	case PwnLocalSMSAdmins:
		return 50 // ??
	case PwnLocalSessionLastDay:
		return 80
	case PwnLocalSessionLastWeek:
		return 55
	case PwnLocalSessionLastMonth:
		return 30
	case PwnWriteAttributeSecurityGUID:
		// This might not work, but you could possibly add an attribute into a weaker attribute set this way
		return 25
	case PwnWriteSPN, PwnWriteValidatedSPN:
		return 30
	case PwnHasSPNNoPreauth, PwnHasSPN:
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&UAC_ACCOUNTDISABLE != 0 {
			// Account is disabled
			return 0
		}
		return 50
	}
	// default
	return 100
}

func AnalyzeObjects(includeobjects, excludeobjects *Objects, lookformethods PwnMethodBitmap, mode string, maxdepth, maxoutgoingconnections int, minprobability Probability) (pg PwnGraph) {
	connectionsmap := make(map[PwnPair]PwnMethodBitmap) // Pwn Connection between objects
	implicatedobjectsmap := make(map[*Object]int)       // Object -> Processed in round n
	canexpand := make(map[*Object]int)

	if excludeobjects == nil {
		excludeobjects = &Objects{}
		excludeobjects.Init(nil)
	}

	// Direction to search, forward = who can pwn interestingobjects, !forward = who can interstingobjects pwn
	forward := strings.HasPrefix(mode, "normal")
	// Backlinks = include all links, don't limit per round
	backlinks := strings.HasSuffix(mode, "backlinks")

	// Convert to our working map
	for _, object := range includeobjects.AsArray() {
		implicatedobjectsmap[object] = 0
	}

	somethingprocessed := true
	processinground := 1
	for somethingprocessed && maxdepth >= processinground {
		somethingprocessed = false
		log.Debug().Msgf("Processing round %v with %v total objects", processinground, len(implicatedobjectsmap))
		newimplicatedobjects := make(map[*Object]struct{})

		for object, processed := range implicatedobjectsmap {
			if processed != 0 {
				continue
			}
			somethingprocessed = true

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
				detectedmethods := pwninfo.Intersect(lookformethods)

				methodcount := detectedmethods.Count()
				if methodcount == 0 || (methodcount == 1 && detectedmethods.IsSet(PwnACLContainsDeny)) {
					// Nothing useful or just a deny ACL, skip it
					continue
				}

				if minprobability > 0 {
					var maxprobability Probability
					for i := PwnMethod(0); i < MaxPwnMethod; i++ {
						if detectedmethods.IsSet(i) {
							probability := CalculateProbability(object, pwntarget, i)
							if probability > maxprobability {
								maxprobability = probability
							}
						}
					}
					if maxprobability < Probability(minprobability) {
						// Too unlikeliy, so we skip it
						continue
					}
				}

				// If we allow backlinks, all pwns are mapped, no matter who is the victim
				// Targets are allowed to pwn each other as a way to reach the goal of pwning all of them
				// If pwner is already processed, we don't care what it can pwn someone more far away from targets
				// If pwner is our attacker, we always want to know what it can do
				targetprocessinground, found := implicatedobjectsmap[pwntarget]
				if pwntarget != AttackerObject &&
					!backlinks &&
					found &&
					targetprocessinground != 0 &&
					targetprocessinground < processinground {
					// skip it
					continue
				}

				if _, found := excludeobjects.Find(DistinguishedName, AttributeValueString(pwntarget.DN())); found {
					// skip excluded objects
					// log.Debug().Msgf("Excluding target %v", pwntarget.DN())
					continue
				}

				newconnectionsmap[PwnPair{Source: object, Target: pwntarget}] = detectedmethods
			}

			if maxoutgoingconnections == 0 || len(newconnectionsmap) < maxoutgoingconnections {
				for pwnpair, detectedmethods := range newconnectionsmap {
					connectionsmap[pwnpair] = detectedmethods
					if _, found := implicatedobjectsmap[pwnpair.Target]; !found {
						newimplicatedobjects[pwnpair.Target] = struct{}{} // Add this to work map as non-processed
					}
				}
				// Add pwn target to graph for processing
			} else {
				log.Debug().Msgf("Outgoing expansion limit hit %v for object %v, there was %v connections", maxoutgoingconnections, object.Label(), len(newconnectionsmap))
				var groupcount int
				for pwnpair := range newconnectionsmap {
					// We assume the number of groups are limited and add them anyway
					if pwnpair.Target.Type() == ObjectTypeGroup {
						groupcount++
					}
				}
				if groupcount < maxoutgoingconnections {
					// Add the groups, but not the rest
					var addedanyway int
					for pwnpair, detectedmethods := range newconnectionsmap {
						// We assume the number of groups are limited and add them anyway
						if pwnpair.Target.Type() == ObjectTypeGroup {
							connectionsmap[pwnpair] = detectedmethods
							if _, found := implicatedobjectsmap[pwnpair.Target]; !found {
								newimplicatedobjects[pwnpair.Target] = struct{}{} // Add this to work map as non-processed
							}
							addedanyway++
						}
					}
					canexpand[object] = len(newconnectionsmap) - addedanyway
				}
			}
			implicatedobjectsmap[object] = processinground // We're done processing this
		}
		log.Debug().Msgf("Processing round %v yielded %v new objects", processinground, len(newimplicatedobjects))
		for newentry := range newimplicatedobjects {
			implicatedobjectsmap[newentry] = 0
		}
		processinground++
	}

	// Convert map to slice
	pg.Connections = make([]PwnConnection, len(connectionsmap))
	i := 0
	for connection, methods := range connectionsmap {
		nc := PwnConnection{
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

	pg.Nodes = make([]GraphObject, len(implicatedobjectsmap))
	i = 0
	for object := range implicatedobjectsmap {
		pg.Nodes[i].Object = object
		if _, found := includeobjects.Find(DistinguishedName, AttributeValueString(object.DN())); found {
			pg.Nodes[i].Target = true
		}
		if expandnum, found := canexpand[object]; found {
			pg.Nodes[i].CanExpand = expandnum
		}
		i++
	}

	return
}
