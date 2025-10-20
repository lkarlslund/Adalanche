package engine

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/lkarlslund/adalanche/modules/ui"
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
	Close() ([]*IndexedGraph, error)
}

type LoaderEstimator interface {
	Estimate(path string, cb ProgressCallbackFunc) error
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

func NewLoaderObjects(ld Loader) *IndexedGraph {
	aos := NewIndexedGraph()
	aos.AddDefaultFlex(DataLoader, NV(ld.Name()))

	// Add the root node
	rootnode := NewNode(Name, ld.Name())
	aos.Add(rootnode)
	aos.SetRoot(rootnode)

	return aos
}

type loaderGraphInfo struct {
	Loader  Loader
	Objects *IndexedGraph
}

// loadWithLoaders runs all registered loaders
func loadWithLoaders(loaders []Loader, paths []string, cb ProgressCallbackFunc) ([]loaderGraphInfo, error) {
	type fs struct {
		filename string
		size     int64
	}
	var files []fs

	for _, path := range paths {
		ui.Info().Msgf("Scanning for data files from %v ...", path)

		if st, err := os.Stat(path); err != nil || !st.IsDir() {
			ui.Warn().Msgf("%v is not a directory", path)
		}

		filepath.Walk(path, func(lpath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				files = append(files, fs{lpath, info.Size()})
			}
			return nil
		})
	}
	ui.Info().Msgf("Will process %v files", len(files))

	// Sort by biggest files first
	sort.Slice(files, func(i, j int) bool {
		return files[i].size > files[j].size
	})

	ui.Debug().Msg("Estimating data to process")
	for _, file := range files {
		for _, loader := range loaders {
			if le, ok := loader.(LoaderEstimator); ok {
				le.Estimate(file.filename, cb)
			} else {
				cb(0, -1)
			}
		}
	}

	ui.Debug().Msg("Processing files with the biggest files first")
	fileQueue := make(chan string, runtime.NumCPU()*4)
	var fileQueueWG sync.WaitGroup
	var skipped uint32
	for i := 0; i < runtime.NumCPU(); i++ {
		fileQueueWG.Add(1)
		go func() {
			for filename := range fileQueue {
				var handled bool
			loaderloop:
				for _, loader := range loaders {
					fileerr := loader.Load(filename, cb)
					switch fileerr {
					case nil:
						handled = true
						break loaderloop
					case ErrUninterested:
						// loop, and try next loader
					default:
						ui.Error().Msgf("Error from loader %v on file %v: %v", loader.Name(), filename, fileerr)
					}
				}
				if !handled {
					atomic.AddUint32(&skipped, 1)
				}
				cb(-1, 0) // Either loaded or skipped
			}
			fileQueueWG.Done()
		}()
	}

	// Feed into the queue
	for _, file := range files {
		fileQueue <- file.filename
	}
	close(fileQueue)

	// Wait for processors to be done
	fileQueueWG.Wait()

	var globalerr error
	var totalNodes int

	ui.Info().Msgf("Loaded %v files, skipped %v files", len(files)-int(skipped), skipped)

	var aos []loaderGraphInfo

	for _, loader := range loaders {
		los, err := loader.Close()
		if err != nil {
			globalerr = err
		}

		var loaderproduced int

		for _, lo := range los {
			loaderproduced += lo.Order()
			totalNodes += lo.Order()
			aos = append(aos, loaderGraphInfo{loader, lo})
		}
		ui.Info().Msgf("Loader %v produced %v nodes in %v graphs", loader.Name(), loaderproduced, len(los))
	}
	ui.Info().Msgf("Loaded a total of %v nodes", totalNodes)
	if totalNodes == 0 {
		globalerr = errors.New("No nodes loaded")
	}

	return aos, globalerr
}
