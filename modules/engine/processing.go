package engine

import (
	"runtime"
	"sort"
	"sync"

	gsync "github.com/SaveTheRbtz/generic-sync-map-go"
	"github.com/lkarlslund/adalanche/modules/ui"
)

func getMergeAttributes() []Attribute {
	var mergeon []Attribute
	attributemutex.RLock()
	for i := range attributeinfos {
		if attributeinfos[i].merge {
			mergeon = append(mergeon, Attribute(i))
		}
	}
	attributemutex.RUnlock()
	sort.Slice(mergeon, func(i, j int) bool {
		isuccess := attributeinfos[mergeon[i]].mergeSuccesses.Load()
		jsuccess := attributeinfos[mergeon[j]].mergeSuccesses.Load()
		return jsuccess < isuccess
	})
	return mergeon
}

func Merge(aos []*Objects) (*Objects, error) {
	var biggest, biggestcount, totalobjects int
	for i, caos := range aos {
		loaderproduced := caos.Len()
		totalobjects += loaderproduced
		if loaderproduced > biggestcount {
			biggestcount = loaderproduced
			biggest = i
		}
	}

	ui.Info().Msgf("Initiating merge with a total of %v objects", totalobjects)

	_ = biggest

	// ui.Info().Msgf("Using object collection with %v objects as target to merge into .... reindexing it", len(globalobjects.Slice()))

	// Find all the attributes that can be merged objects on
	globalobjects := NewObjects()
	globalroot := NewObject(
		Name, NewAttributeValueString("Adalanche root node"),
		Type, NewAttributeValueString("Root"),
	)
	globalobjects.SetRoot(globalroot)
	orphancontainer := NewObject(Name, NewAttributeValueString("Orphans"))
	orphancontainer.ChildOf(globalroot)
	globalobjects.Add(orphancontainer)

	ui.Info().Msgf("Merging %v objects into the object metaverse", totalobjects)

	pb := ui.ProgressBar("Merging objects from each unique source", int64(totalobjects))

	// To ease anti-cross-the-beams on DataSource we temporarily group each source and combine them in the end
	type sourceinfo struct {
		queue chan *Object
		shard *Objects
	}

	var sourcemap gsync.MapOf[string, sourceinfo]

	var consumerWG, producerWG sync.WaitGroup

	// Iterate over all the object collections
	for _, mergeobjects := range aos {
		if mergeroot := mergeobjects.Root(); mergeroot != nil {
			mergeroot.ChildOf(globalroot)
		}

		// Merge all objects into their own shard based on the DataSource attribute if any
		producerWG.Add(1)
		go func(os *Objects) {
			nextshard := sourceinfo{
				queue: make(chan *Object, 64),
				shard: NewObjects(),
			}

			os.Iterate(func(mergeobject *Object) bool {
				pb.Add(1)
				ds := mergeobject.OneAttr(DataSource)
				if ds != nil {
					ds = AttributeValueToIndex(ds)
				} else {
					ds = NewAttributeValueString("")
				}

				info, loaded := sourcemap.LoadOrStore(ds.String(), nextshard)
				if !loaded {
					consumerWG.Add(1)
					go func(shard *Objects, queue chan *Object) {
						var i int
						mergeon := getMergeAttributes()
						for mergeobject := range queue {
							if i%16384 == 0 {
								mergeon = getMergeAttributes()
							}
							shard.AddMerge(mergeon, mergeobject)
							i++
						}
						consumerWG.Done()
					}(info.shard, info.queue)
					nextshard = sourceinfo{
						queue: make(chan *Object, 64),
						shard: NewObjects(),
					}
				}
				info.queue <- mergeobject
				return true
			})
			producerWG.Done()
		}(mergeobjects)
	}

	producerWG.Wait()
	sourcemap.Range(func(key string, value sourceinfo) bool {
		close(value.queue)
		return true
	})
	consumerWG.Wait()
	pb.Finish()

	var needsfinalization int
	sourcemap.Range(func(key string, value sourceinfo) bool {
		needsfinalization += value.shard.Len()
		return true
	})

	pb = ui.ProgressBar("Finalizing merge", int64(needsfinalization))

	// We're grabbing the index directly for faster processing here
	dnindex := globalobjects.GetIndex(DistinguishedName)

	mergeon := getMergeAttributes()

	// Just add these. they have a DataSource so we're not merging them EXCEPT for ones with a DistinguishedName collision FME
	sourcemap.Range(func(us string, usao sourceinfo) bool {
		if us == "" {
			return true // continue - not these, we'll try to merge at the very end
		}
		usao.shard.Iterate(func(addobject *Object) bool {
			pb.Add(1)
			// Here we'll deduplicate DNs, because sometimes schema and config context slips in twice ...

			// FIXME - THIS ISN'T WORKING
			// aosid := addobject.SID()
			// if !aosid.IsBlank() && aosid.Component(2) == 21 {
			// 	// Always merge these, they might belong elsewhere
			// 	globalobjects.AddMerge(mergeon, addobject)
			// 	return true
			// }

			// Skip duplicate DNs entirely, just absorb them (solves the issue of duplicates due to shared configuration context etc)
			if dn := addobject.OneAttr(DistinguishedName); dn != nil {
				if existing, exists := dnindex.Lookup(AttributeValueToIndex(dn)); exists {
					existing.First().AbsorbEx(addobject, true)
					return true
				}
			}

			globalobjects.Add(addobject)
			return true
		})
		return true
	})

	nodatasource, _ := sourcemap.Load("")
	var i int
	nodatasource.shard.Iterate(func(addobject *Object) bool {
		pb.Add(1)
		// Here we'll deduplicate DNs, because sometimes schema and config context slips in twice
		// if dn := addobject.OneAttr(DistinguishedName); dn != nil {
		// 	if existing, exists := dnindex.Lookup(AttributeValueToIndex(dn)); exists {
		// 		existing.First().AbsorbEx(addobject, true)
		// 		return true
		// 	}
		// }
		if i%16384 == 0 {
			// Refresh the list of attributes, ordered by most successfull first
			mergeon = getMergeAttributes()
		}
		globalobjects.AddMerge(mergeon, addobject)
		i++
		return true
	})

	pb.Finish()

	aftermergetotalobjects := globalobjects.Len()
	ui.Info().Msgf("After merge we have %v objects in the metaverse (merge eliminated %v objects)", aftermergetotalobjects, totalobjects-aftermergetotalobjects)

	runtime.GC()

	var orphans int
	processed := make(map[ObjectID]struct{})
	var processobject func(o *Object)
	processobject = func(o *Object) {
		if _, done := processed[o.ID()]; !done {
			if _, found := globalobjects.FindID(o.ID()); !found {
				ui.Debug().Msgf("Child object %v wasn't added to index, fixed", o.Label())
				globalobjects.Add(o)
			}
			processed[o.ID()] = struct{}{}
			o.Children().Iterate(func(child *Object) bool {
				processobject(child)
				return true
			})
		}
	}
	globalobjects.Iterate(func(object *Object) bool {
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

	return globalobjects, nil
}
