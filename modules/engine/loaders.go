package engine

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/lkarlslund/adalanche/modules/ui"
)

type LoaderID int

type Loader interface {
	Name() string

	// Init is called before any loads are done, with where to load to.
	Init(target LoadTarget) error

	// Load will be offered a file, and can either return UnininterestedError, nil or any error it
	// wishes. UninterestedError will pass the file to the next loader, Nil means it accepted and processed the file,
	// and any other error will stop processing the file and display an error
	Load(path string, cb ProgressCallbackFunc) error

	// Close signals that no more files are coming. Everything the loader
	// staged must be committed when it returns.
	Close() error
}

// LoadTarget is where a loader writes: the shared graph, through load
// transactions (see BeginLoad), under the loader's own root node.
type LoadTarget struct {
	graph *IndexedGraph
	id    LoaderID
	root  *Node
	name  string
}

// NewLoadTarget makes a root node for a loader and returns the target for
// it. The root joins g with the loader's first commit, so a loader that finds
// nothing leaves nothing behind.
func NewLoadTarget(g *IndexedGraph, loaderName string) LoadTarget {
	return newLoadTarget(g, -1, loaderName)
}

func newLoadTarget(g *IndexedGraph, id LoaderID, loaderName string) LoadTarget {
	root := NewNode(Name, NV(loaderName), DataLoader, NV(loaderName))
	t := LoadTarget{graph: g, id: id, root: root, name: loaderName}
	t.register()
	return t
}

// register records whose nodes the loader's loader-phase processors see.
func (t LoadTarget) register() {
	if t.id < 0 {
		return
	}
	if t.graph.loaderScopes == nil {
		t.graph.loaderScopes = map[LoaderID]string{}
	}
	t.graph.loaderScopes[t.id] = t.name
}

// Begin starts a load transaction for the loader. Its identities resolve
// among everything the loader committed, such as the same directory object
// seen from several domains.
func (t LoadTarget) Begin(name string) *Tx {
	return t.graph.BeginLoad(name, t.name, t.root)
}

// BeginCollection starts a load transaction for one self-contained
// collection, such as one machine's: the identities it stages resolve only
// within it, never with another collection's, even when they look alike
// (two machines with the same name). Other data joins it when references are
// resolved after loading.
func (t LoadTarget) BeginCollection(name string) *Tx {
	tx := t.graph.BeginLoad(name, t.name, t.root)
	tx.collection = true
	return tx
}

// Root is the loader's root node.
func (t LoadTarget) Root() *Node { return t.root }

// As returns the target under another loader name: its nodes carry that
// name as their data loader and resolve identities among that loader's
// nodes, for a loader that loads another's kind of data.
func (t LoadTarget) As(loaderName string) LoadTarget {
	t.name = loaderName
	t.register()
	return t
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

// loadWithLoaders runs all registered loaders
func loadWithLoaders(g *IndexedGraph, loaders []Loader, paths []string, cb ProgressCallbackFunc) error {
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
			if collection.IsStaging(info.Name()) {
				// Output that is still being written, or was abandoned.
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
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
	ui.Info().Msgf("Loaded %v files, skipped %v files", len(files)-int(skipped), skipped)
	before := g.Order()
	for _, loader := range loaders {
		if err := loader.Close(); err != nil {
			globalerr = err
		}
		ui.Info().Msgf("Loader %v done, graph has %v nodes", loader.Name(), g.Order())
	}
	if g.Order() == before {
		globalerr = errors.New("no nodes loaded")
	}
	return globalerr
}
