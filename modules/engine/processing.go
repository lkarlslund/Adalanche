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

	globalobjects := aos[biggest]
	globalobjects.Reindex()

	globalroot := NewObject(
		Name, AttributeValueString("adalanche root node"),
		ObjectCategorySimple, AttributeValueString("Root"),
	)
	globalobjects.Add(globalroot)
	globalobjects.SetRoot(globalroot)

	orphancontainer := NewObject(Name, AttributeValueString("Orphans"))
	orphancontainer.ChildOf(globalroot)
	globalobjects.Add(orphancontainer)

	globalroot.Adopt(aos[biggest].Root())
	for _, object := range aos[biggest].Slice() {
		globalobjects.Add(object)
	}

	for i, mergeobjects := range aos {
		if i == biggest {
			continue
		}

		if mergeroot := mergeobjects.Root(); mergeroot != nil {
			globalroot.Adopt(mergeroot)
		}

		log.Info().Msgf("Merging %v objects into the object metaverse", len(mergeobjects.Slice()))
		globalobjects.AddMerge([]Attribute{ObjectSid, GPCFileSysPath, DownLevelLogonName}, mergeobjects.Slice()...)
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
