package analyze

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/rs/zerolog/log"
	"github.com/schollz/progressbar/v3"
)

type Loader interface {
	Name() string

	// Init is called before any loads are done
	Init(ao *engine.Objects) error

	// Load will be offered a file, and can either return UnininterestedError, nil or any error it
	// wishes. UninterestedError will pass the file to the next loader, Nil means it accepted and processed the file,
	// and any other error will stop processing the file and display an error
	Load(path string, pb *progressbar.ProgressBar) error

	// Close signals that no more files are coming
	Close() error
}

var (
	UninterestedError = errors.New("Plugin is not interested in this file, try harder")

	loaders []Loader
)

func RegisterLoader(loader Loader) {
	loaders = append(loaders, loader)
}

func RunLoaders(path string) (*engine.Objects, error) {
	if st, err := os.Stat(path); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%v is no a directory", path)
	}

	// All loaders get their own Objects to add to, so thread safety is up to the loader
	// This also ensures that a loader doesnt try to cheat and merge stuff it should'nt know about
	aos := make([]*engine.Objects, len(loaders))
	for i, loader := range loaders {
		aos[i] = &engine.Objects{}
		aos[i].Init()
		aos[i].SetDefaultSource(engine.AttributeValueString(loader.Name()))

		// Add the root node
		aos[i].Add(engine.NewObject(engine.Name, engine.AttributeValueString(loader.Name())))

		log.Debug().Msgf("Initializing loader %v", loader.Name())
		err := loader.Init(aos[i])
		if err != nil {
			return nil, err
		}
	}

	log.Info().Msgf("Scanning for data files from %v ...", path)
	var files []string
	filepath.Walk(path, func(lpath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, lpath)
		}
		return nil
	})
	log.Debug().Msgf("Will process %v files", len(files))

	pb := progressbar.NewOptions(len(files),
		progressbar.OptionSetDescription("Loading data"),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetItsString("tidbits"),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
		progressbar.OptionThrottle(time.Second*1),
	)

	var skipped int
	for _, file := range files {
		var fileerr error
	loaderloop:
		for _, loader := range loaders {
			fileerr = loader.Load(file, pb)
			switch fileerr {
			case nil:
				break loaderloop
			case UninterestedError:
				// loop, and try next loader
			default:
				log.Error().Msgf("Error from loader %v: %v", loader.Name(), fileerr)
				// return fileerr
			}
		}
		if fileerr != nil {
			skipped++
		}
		pb.Add(1) // Either loaded or skipped
	}
	pb.Finish()

	log.Info().Msgf("Loaded %v files, skipped %v files", len(files)-skipped, skipped)

	var biggest, biggestcount, totalobjects int
	for i, loader := range loaders {
		err := loader.Close()
		if err != nil {
			return nil, err
		}
		loaderproduced := len(aos[i].Slice())
		totalobjects += loaderproduced
		if loaderproduced > biggestcount {
			biggestcount = loaderproduced
			biggest = i
		}
		log.Info().Msgf("Loader %v produced %v objects", loader.Name(), loaderproduced)
	}
	log.Info().Msgf("We have a total of %v objects, initiating merge", totalobjects)

	// Some enrichment needed - can this be done in pre-processing?

	// Now merge everything together using the biggest as the target and merging all the smaller stuff into that ...
	// mergeinto := &engine.Objects{}
	// mergeinto.Init(nil)

	// _ = biggest

	globalobjects := &engine.Objects{}
	globalobjects.Init()

	globalroot := engine.NewObject(engine.Name, engine.AttributeValueString("adalanche root node"))
	globalobjects.Add(globalroot)

	orphancontainer := engine.NewObject(engine.Name, engine.AttributeValueString("Orphans"))
	orphancontainer.ChildOf(globalroot)
	globalobjects.Add(orphancontainer)

	globalroot.Adopt(aos[biggest].Root())
	for _, object := range aos[biggest].Slice() {
		globalobjects.Add(object)
	}

	for i, loader := range loaders {
		if i == biggest {
			continue
		}
		mergeobjects := aos[i]

		globalroot.Adopt(mergeobjects.Root())

		log.Info().Msgf("Merging %v objects from %v into the object metaverse", len(mergeobjects.Slice()), loader.Name())
		globalobjects.AddMerge([]engine.Attribute{engine.ObjectSid, engine.GPCFileSysPath}, mergeobjects.Slice()...)
	}

	aftermergetotalobjects := len(globalobjects.Slice())
	log.Info().Msgf("After merge we have %v objects in the metaverse (merge eliminated %v objects)", aftermergetotalobjects, totalobjects-aftermergetotalobjects)

	var orphans int
	processed := make(map[uint32]struct{})
	var processobject func(o *engine.Object)
	processobject = func(o *engine.Object) {
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
