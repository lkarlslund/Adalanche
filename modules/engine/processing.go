package engine

import "github.com/rs/zerolog/log"

func Merge(aos []*Objects) (*Objects, error) {
	var biggest, biggestcount, totalobjects int
	for i, caos := range aos {
		loaderproduced := len(caos.Slice())
		totalobjects += loaderproduced
		if loaderproduced > biggestcount {
			biggestcount = loaderproduced
			biggest = i
		}
	}
	log.Info().Msgf("Initiating merge with a total of %v objects", totalobjects)

	globalobjects := aos[biggest]

	log.Info().Msgf("Using object collection with %v objects as target to merge into .... reindexing it", len(globalobjects.Slice()))

	globalobjects.Reindex()

	globalroot := NewObject(
		Name, AttributeValueString("adalanche root node"),
		ObjectCategorySimple, AttributeValueString("Root"),
	)

	if oldroot := globalobjects.Root(); oldroot != nil {
		oldroot.ChildOf(globalroot)
	}

	globalobjects.SetRoot(globalroot)

	orphancontainer := NewObject(Name, AttributeValueString("Orphans"))
	orphancontainer.ChildOf(globalroot)
	globalobjects.Add(orphancontainer)

	needsmergeobjects := &Objects{}
	needsmergeobjects.Init()

	mergeon := []Attribute{ObjectSid, GPCFileSysPath, DownLevelLogonName, MACAddress, IPAddress, Hostname} // FIXME

	for i, mergeobjects := range aos {
		if i == biggest {
			continue
		}

		if mergeroot := mergeobjects.Root(); mergeroot != nil {
			mergeroot.ChildOf(globalroot)
		}

		needsmergeobjects.AddMerge(mergeon, mergeobjects.Slice()...)
	}

	needsmerge := needsmergeobjects.Slice()
	merged := make([]bool, len(needsmerge))

	log.Info().Msgf("Merging %v objects into the object metaverse", len(needsmerge))

	round := 1
	for {
		var mergecount int
		for i, mergeobject := range needsmerge {
			if !merged[i] {
				if globalobjects.Merge(mergeon, mergeobject) {
					merged[i] = true
					mergecount++
				}
			}
		}

		log.Info().Msgf("Merged %v objects in round %v", mergecount, round)
		if mergecount == 0 {
			// nothing merged, just add the rest
			break
		}
		round++
	}

	log.Info().Msgf("Adding the last unmerged objects ...")
	for i, mergeobject := range needsmerge {
		if !merged[i] {
			globalobjects.Add(mergeobject)
		}
	}

	aftermergetotalobjects := len(globalobjects.Slice())
	log.Info().Msgf("After merge we have %v objects in the metaverse (merge eliminated %v objects)", aftermergetotalobjects, totalobjects-aftermergetotalobjects)

	var orphans int
	processed := make(map[uint32]struct{})
	var processobject func(o *Object)
	processobject = func(o *Object) {
		if _, done := processed[o.ID()]; !done {
			if _, found := globalobjects.FindByID(o.ID()); !found {
				log.Debug().Msgf("Child object %v wasn't added to index, fixed", o.Label())
				globalobjects.Add(o)
			}
			processed[o.ID()] = struct{}{}
			for _, child := range o.Children() {
				processobject(child)
			}
		}
	}
	for _, object := range globalobjects.Slice() {
		if object.Parent() == nil {
			object.ChildOf(orphancontainer)
			orphans++
		}
		processobject(object)
	}
	if orphans > 0 {
		log.Warn().Msgf("Detected %v orphan objects in final results", orphans)
	}

	return globalobjects, nil
}
