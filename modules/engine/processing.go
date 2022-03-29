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

	globalobjects := NewObjects()
	_ = biggest
	// globalobjects := aos[biggest]

	// log.Info().Msgf("Using object collection with %v objects as target to merge into .... reindexing it", len(globalobjects.Slice()))

	// After merge we don't need all the indexes
	globalobjects.DropIndexes()

	// Let's not change anything in the original objects
	globalobjects.DefaultValues = nil

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

	// Find all the attributes that can be merged objects on
	var mergeon []Attribute
	for i, ai := range attributenums {
		if ai.merge {
			mergeon = append(mergeon, Attribute(i))
		}
	}

	var needsmerge []*Object

	// Iterate over all the object collections
	for _, mergeobjects := range aos {
		if mergeroot := mergeobjects.Root(); mergeroot != nil {
			mergeroot.ChildOf(globalroot)
		}

		needsmerge = append(needsmerge, mergeobjects.Slice()...)
	}

	log.Info().Msgf("Merging %v objects into the object metaverse", len(needsmerge))

	pb := progressbar.NewOptions(len(needsmerge),
		progressbar.OptionSetDescription("Merging objects ..."),
		progressbar.OptionShowCount(), progressbar.OptionShowIts(), progressbar.OptionSetItsString("objects"),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
		progressbar.OptionThrottle(time.Second*1),
	)

	// To ease anti-cross-the-beams on UniqueSource we temporarily group each source and combine them in the end
	sourcemap := make(map[string]*Objects)

	nosourceobjects := NewObjects()

	for _, mergeobject := range needsmerge {
		if mergeobject.HasAttr(UniqueSource) {
			us := mergeobject.OneAttrString(UniqueSource)
			if sourcemap[us] == nil {
				sourcemap[us] = NewObjects()
			}
			sourcemap[us].AddMerge(mergeon, mergeobject)
		} else {
			nosourceobjects.AddMerge(mergeon, mergeobject)
		}
		pb.Add(1)
	}

	for _, usao := range sourcemap {
		globalobjects.Add(usao.Slice()...)
	}

	globalobjects.AddMerge(mergeon, nosourceobjects.Slice()...)

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
