package engine

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/schollz/progressbar/v3"
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

	log.Info().Msgf("Initiating merge with a total of %v objects", totalobjects)

	_ = biggest

	// log.Info().Msgf("Using object collection with %v objects as target to merge into .... reindexing it", len(globalobjects.Slice()))

	// Find all the attributes that can be merged objects on
	var mergeon []Attribute
	for i, ai := range attributenums {
		if ai.merge {
			mergeon = append(mergeon, Attribute(i))
		}
	}

	globalobjects := NewObjects()
	globalroot := NewObject(
		Name, AttributeValueString("adalanche root node"),
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

	log.Info().Msgf("Merging %v objects into the object metaverse", len(needsmerge))

	pb := progressbar.NewOptions(len(needsmerge),
		progressbar.OptionSetDescription("Merging objects from each unique source ..."),
		progressbar.OptionShowCount(), progressbar.OptionShowIts(), progressbar.OptionSetItsString("objects"),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
		progressbar.OptionThrottle(time.Second*1),
	)

	// To ease anti-cross-the-beams on UniqueSource we temporarily group each source and combine them in the end
	sourcemap := make(map[interface{}]*Objects)
	none := ""
	sourcemap[none] = NewObjects()

	for mergeobject, _ := range needsmerge {
		if mergeobject.HasAttr(UniqueSource) {
			us := attributeValueToIndex(mergeobject.OneAttr(UniqueSource))
			if sourcemap[us] == nil {
				sourcemap[us] = NewObjects()
			}
			sourcemap[us].AddMerge(mergeon, mergeobject)
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

	pb = progressbar.NewOptions(needsfinalization,
		progressbar.OptionSetDescription("Finalizing merge ..."),
		progressbar.OptionShowCount(), progressbar.OptionShowIts(), progressbar.OptionSetItsString("objects"),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
		progressbar.OptionThrottle(time.Second*1),
	)

	for _, usao := range sourcemap {
		for _, addobject := range usao.Slice() {
			pb.Add(1)
			// Here we'll deduplicate DNs, because sometimes schema and config context slips in twice
			if addobject.HasAttr(DistinguishedName) {
				if existing, exists := globalobjects.Find(DistinguishedName, addobject.OneAttr(DistinguishedName)); exists {
					existing.AbsorbEx(addobject, true)
					continue
				}
			}
			globalobjects.Add(addobject)
		}
	}

	pb.Finish()

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
