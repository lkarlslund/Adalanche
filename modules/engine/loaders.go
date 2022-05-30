package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/rs/zerolog/log"
)

type LoaderID int

type Loader interface {
	Name() string

	// Init is called before any loads are done
	Init() error

	// Load will be offered a file, and can either return UnininterestedError, nil or any error it
	// wishes. UninterestedError will pass the file to the next loader, Nil means it accepted and processed the file,
	// and any other error will stop processing the file and display an error
	Load(path string, cb ProgressCallbackFunc) error

	// Close signals that no more files are coming
	Close() ([]*Objects, error)
}

var (
	ErrUninterested = errors.New("plugin is not interested in this file, try harder")

	loadergenerators []LoaderGenerator
)

type LoaderGenerator func() Loader

func AddLoader(lg LoaderGenerator) LoaderID {
	loadergenerators = append(loadergenerators, lg)
	return LoaderID(len(loadergenerators) - 1)
}

func NewLoaderObjects(ld Loader) *Objects {
	aos := NewObjects()
	aos.AddDefaultFlex(MetaDataSource, AttributeValueString(ld.Name()))

	// Add the root node
	rootnode := NewObject(Name, ld.Name())
	aos.Add(rootnode)
	aos.SetRoot(rootnode)

	return aos
}

type loaderobjects struct {
	Loader  Loader
	Objects *Objects
}

// Load runs all registered loaders
func Load(loaders []Loader, path string, cb ProgressCallbackFunc) ([]loaderobjects, error) {
	if st, err := os.Stat(path); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%v is no a directory", path)
	}

	log.Info().Msgf("Scanning for data files from %v ...", path)
	type fs struct {
		filename string
		size     int64
	}

	var files []fs
	filepath.Walk(path, func(lpath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, fs{lpath, info.Size()})
		}
		return nil
	})
	log.Info().Msgf("Will process %v files", len(files))

	// Sort by biggest files first
	sort.Slice(files, func(i, j int) bool {
		return files[i].size > files[j].size
	})

	log.Debug().Msg("Processing files with the biggest files first")

	cb(0, len(files))

	var skipped int
	for _, file := range files {
		fileerr := ErrUninterested
	loaderloop:
		for _, loader := range loaders {
			fileerr = loader.Load(file.filename, cb)
			switch fileerr {
			case nil:
				break loaderloop
			case ErrUninterested:
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

	var aos []loaderobjects

	for _, loader := range loaders {
		los, err := loader.Close()
		if err != nil {
			globalerr = err
		}

		var loaderproduced int

		for _, lo := range los {
			loaderproduced += lo.Len()
			totalobjects += lo.Len()
			aos = append(aos, loaderobjects{loader, lo})
		}
		log.Info().Msgf("Loader %v produced %v objects in %v collections", loader.Name(), loaderproduced, len(los))
	}
	log.Info().Msgf("We produced a total of %v objects from %v", totalobjects, path)

	return aos, globalerr
}
