package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
)

const PostProcessing LoaderID = -1

type LoaderID int

type Loader interface {
	Name() string

	// Init is called before any loads are done
	Init(ao *Objects) error

	// Load will be offered a file, and can either return UnininterestedError, nil or any error it
	// wishes. UninterestedError will pass the file to the next loader, Nil means it accepted and processed the file,
	// and any other error will stop processing the file and display an error
	Load(path string, cb ProgressCallbackFunc) error

	// Close signals that no more files are coming
	Close() error
}

var (
	UninterestedError = errors.New("Plugin is not interested in this file, try harder")

	loaders []Loader
)

func AddLoader(loader Loader) LoaderID {
	loaders = append(loaders, loader)
	return LoaderID(len(loaders) - 1)
}

// Load runs all registered loaders
func Load(path string, cb ProgressCallbackFunc) ([]*Objects, error) {
	if st, err := os.Stat(path); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%v is no a directory", path)
	}

	// All loaders get their own Objects to add to, so thread safety is up to the loader
	// This also ensures that a loader doesnt try to cheat and merge stuff it should'nt know about
	aos := make([]*Objects, len(loaders))
	for i, loader := range loaders {
		aos[i] = &Objects{}
		aos[i].Init()
		aos[i].SetDefaultSource(AttributeValueString(loader.Name()))

		// Add the root node
		rootnode := NewObject(Name, AttributeValueString(loader.Name()))
		// aos[i].Add(rootnode)
		aos[i].SetRoot(rootnode)

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

	cb(0, len(files))

	var skipped int
	for _, file := range files {
		var fileerr error
	loaderloop:
		for _, loader := range loaders {
			fileerr = loader.Load(file, cb)
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
		cb(-1, 0) // Either loaded or skipped
	}
	// pb.Finish()

	var globalerr error
	var totalobjects int

	log.Info().Msgf("Loaded %v files, skipped %v files", len(files)-skipped, skipped)
	for i, loader := range loaders {
		err := loader.Close()
		if err != nil {
			globalerr = err
		}
		loaderproduced := len(aos[i].Slice())
		totalobjects += loaderproduced
		log.Info().Msgf("Loader %v produced %v objects", loader.Name(), loaderproduced)
	}
	log.Info().Msgf("We have a total of %v objects, initiating merge", totalobjects)

	return aos, globalerr
}
