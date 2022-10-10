package engine

import (
	"github.com/lkarlslund/adalanche/modules/ui"
)

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

	ui.Info().Msgf("Initiating merge with a total of %v objects", totalobjects)

	_ = biggest

	// ui.Info().Msgf("Using object collection with %v objects as target to merge into .... reindexing it", len(globalobjects.Slice()))

	// Find all the attributes that can be merged objects on
	var mergeon []Attribute
	for i, ai := range attributenums {
		if ai.merge {
			mergeon = append(mergeon, Attribute(i))
		}
	}

	globalobjects := NewObjects()
	globalroot := NewObject(
		Name, AttributeValueString("Adalanche root node"),
		ObjectCategorySimple, AttributeValueString("Root"),
	)
	globalobjects.SetRoot(globalroot)
	orphancontainer := NewObject(Name, AttributeValueString("Orphans"))
	orphancontainer.ChildOf(globalroot)
	globalobjects.Add(orphancontainer)

	// Iterate over all the object collections
	needsmerge := make(map[*Object]struct{})

	for _, mergeobjects := range aos {
		if mergeroot := mergeobjects.Root(); mergeroot != nil {
			mergeroot.ChildOf(globalroot)
		}

		for _, o := range mergeobjects.Slice() {
			needsmerge[o] = struct{}{}
		}
		// needsmerge = append(needsmerge, mergeobjects.Slice()...)
	}

	ui.Info().Msgf("Merging %v objects into the object metaverse", len(needsmerge))

	pb := ui.ProgressBar("Merging objects from each unique source ...", len(needsmerge))

	// To ease anti-cross-the-beams on UniqueSource we temporarily group each source and combine them in the end
	sourcemap := make(map[interface{}]*Objects)
	none := ""
	sourcemap[none] = NewObjects()

	for mergeobject, _ := range needsmerge {
		if mergeobject.HasAttr(DataSource) {
			us := AttributeValueToIndex(mergeobject.OneAttr(DataSource))
			shard := sourcemap[us]
			if shard == nil {
				shard = NewObjects()
				sourcemap[us] = shard
			}
			shard.AddMerge(mergeon, mergeobject)
		} else {
			sourcemap[none].AddMerge(mergeon, mergeobject)
		}
		pb.Add(1)
	}

	pb.Finish()

	var needsfinalization int
	for _, sao := range sourcemap {
		needsfinalization += sao.Len()
	}

	pb = ui.ProgressBar("Finalizing merge ...", needsfinalization)

	// We're grabbing the index directly for faster processing here
	dnindex := globalobjects.GetIndex(DistinguishedName)

	for us, usao := range sourcemap {
		if us == none {
			continue // not these, we'll try to merge at the very end
		}
		for _, addobject := range usao.Slice() {
			pb.Add(1)
			// Here we'll deduplicate DNs, because sometimes schema and config context slips in twice
			if dn := addobject.OneAttr(DistinguishedName); dn != nil {
				if existing, exists := dnindex.Lookup(AttributeValueToIndex(dn)); exists {
					existing[0].AbsorbEx(addobject, true)
					continue
				}
			}
			globalobjects.Add(addobject)
		}
	}

	for _, addobject := range sourcemap[none].Slice() {
		pb.Add(1)
		// Here we'll deduplicate DNs, because sometimes schema and config context slips in twice
		if dn := addobject.OneAttr(DistinguishedName); dn != nil {
			if existing, exists := dnindex.Lookup(AttributeValueToIndex(dn)); exists {
				existing[0].AbsorbEx(addobject, true)
				continue
			}
		}
		globalobjects.AddMerge(mergeon, addobject)
	}

	pb.Finish()

	aftermergetotalobjects := len(globalobjects.Slice())
	ui.Info().Msgf("After merge we have %v objects in the metaverse (merge eliminated %v objects)", aftermergetotalobjects, totalobjects-aftermergetotalobjects)

	var orphans int
	processed := make(map[uint32]struct{})
	var processobject func(o *Object)
	processobject = func(o *Object) {
		if _, done := processed[o.ID()]; !done {
			if _, found := globalobjects.FindByID(o.ID()); !found {
				ui.Debug().Msgf("Child object %v wasn't added to index, fixed", o.Label())
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
		ui.Warn().Msgf("Detected %v orphan objects in final results", orphans)
	}

	return globalobjects, nil
}
