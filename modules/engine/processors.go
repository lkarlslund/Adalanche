package engine

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/adalanche/modules/ui"
)

type ProgressCallbackFunc func(progress int, totalprogress int)

type ProcessorFunc func(ao *IndexedGraph)
type ReadOnlyProcessorFunc func(view *FrozenGraph)
type NodePatchProcessorFunc func(view *FrozenGraph, out *NodePatchSet)
type EdgeDeltaProcessorFunc func(view *FrozenGraph, out *EdgeDelta)

// Phase says which graph a processor works on.
type Phase int

const (
	// BeforeMerge processors run on each loader's own graph, before the
	// graphs are merged. Only processors of the same loader see each other.
	BeforeMerge Phase = iota
	// AfterMerge processors run on the merged graph, for all loaders.
	AfterMerge
)

func (p Phase) String() string {
	switch p {
	case BeforeMerge:
		return "before merge"
	case AfterMerge:
		return "after merge"
	}
	return fmt.Sprintf("phase %d", int(p))
}

// Product names something processors make, such as an edge type or tags, so
// processors that use it run after every processor that makes it.
type Product string

// Processor describes when a processor runs. A processor runs after every
// processor in its phase that provides a product it needs; products made in
// an earlier phase are already there. A final processor runs after every
// processor of its phase that is not final.
type Processor struct {
	Description string
	Phase       Phase
	Needs       []Product
	Provides    []Product
	Final       bool
}

type ProcessorKind int

const (
	ProcessorKindGraphMutator ProcessorKind = iota
	ProcessorKindReadOnly
	ProcessorKindNodePatch
	ProcessorKindEdgeDelta
)

type processorInfo struct {
	Processor
	loader    LoaderID
	kind      ProcessorKind
	mutator   ProcessorFunc
	readOnly  ReadOnlyProcessorFunc
	nodePatch NodePatchProcessorFunc
	edgeDelta EdgeDeltaProcessorFunc
}

var registeredProcessors []processorInfo

// ProcessorTiming is how long one processor took on one graph.
type ProcessorTiming struct {
	Description string
	Phase       Phase
	Duration    time.Duration
}

var (
	timingsMutex sync.Mutex
	timings      []ProcessorTiming
)

// ProcessorTimings returns how long each processor took since the program
// started, one entry per processor and graph.
func ProcessorTimings() []ProcessorTiming {
	timingsMutex.Lock()
	defer timingsMutex.Unlock()
	return slices.Clone(timings)
}

func recordTiming(p processorInfo, start time.Time) {
	timingsMutex.Lock()
	timings = append(timings, ProcessorTiming{Description: p.Description, Phase: p.Phase, Duration: time.Since(start)})
	timingsMutex.Unlock()
}

func (l LoaderID) AddProcessor(pf ProcessorFunc, p Processor) {
	registeredProcessors = append(registeredProcessors, processorInfo{Processor: p, loader: l, kind: ProcessorKindGraphMutator, mutator: pf})
}

func (l LoaderID) AddReadOnlyProcessor(pf ReadOnlyProcessorFunc, p Processor) {
	registeredProcessors = append(registeredProcessors, processorInfo{Processor: p, loader: l, kind: ProcessorKindReadOnly, readOnly: pf})
}

func (l LoaderID) AddNodePatchProcessor(pf NodePatchProcessorFunc, p Processor) {
	registeredProcessors = append(registeredProcessors, processorInfo{Processor: p, loader: l, kind: ProcessorKindNodePatch, nodePatch: pf})
}

func (l LoaderID) AddEdgeDeltaProcessor(pf EdgeDeltaProcessorFunc, p Processor) {
	registeredProcessors = append(registeredProcessors, processorInfo{Processor: p, loader: l, kind: ProcessorKindEdgeDelta, edgeDelta: pf})
}

// AnyLoader selects the processors of every loader.
const AnyLoader LoaderID = -1

// RunPhase runs the processors of loader l (or AnyLoader) for phase, each
// after the processors it depends on.
func RunPhase(ao *IndexedGraph, l LoaderID, phase Phase) error {
	return runProcessors(ao, phase, selectProcessors(l, phase, nil))
}

// RunProviders runs only the processors of loader l (or AnyLoader) for
// phase that provide one of products, in dependency order among
// themselves. It is meant for tests of a few processors.
func RunProviders(ao *IndexedGraph, l LoaderID, phase Phase, products ...Product) error {
	return runProcessors(ao, phase, selectProcessors(l, phase, products))
}

func selectProcessors(l LoaderID, phase Phase, products []Product) []processorInfo {
	var selected []processorInfo
	for _, p := range registeredProcessors {
		if (l != AnyLoader && p.loader != l) || p.Phase != phase {
			continue
		}
		if products != nil && !slices.ContainsFunc(p.Provides, func(pr Product) bool { return slices.Contains(products, pr) }) {
			continue
		}
		selected = append(selected, p)
	}
	return selected
}

// processorOrder sorts processors into dependency order. It returns, for
// each processor, the indexes of the processors it must wait for.
func processorOrder(processors []processorInfo, phase Phase) ([][]int, error) {
	// A stable order of processors that are free to run, so results never
	// depend on registration order.
	slices.SortStableFunc(processors, func(a, b processorInfo) int {
		return cmp.Or(cmp.Compare(a.Description, b.Description), cmp.Compare(a.loader, b.loader))
	})

	providers := map[Product][]int{}
	for i, p := range processors {
		for _, product := range p.Provides {
			providers[product] = append(providers[product], i)
		}
	}
	earlier := map[Product]bool{}
	for _, p := range registeredProcessors {
		if p.Phase < phase {
			for _, product := range p.Provides {
				earlier[product] = true
			}
		}
	}

	waitsFor := make([][]int, len(processors))
	for i, p := range processors {
		for _, product := range p.Needs {
			if len(providers[product]) == 0 && !earlier[product] && !providedAnywhere(product, phase) {
				return nil, fmt.Errorf("processor %q needs %q, which no processor provides", p.Description, product)
			}
			for _, j := range providers[product] {
				if j != i {
					waitsFor[i] = append(waitsFor[i], j)
				}
			}
		}
		if p.Final {
			for j, q := range processors {
				if !q.Final {
					waitsFor[i] = append(waitsFor[i], j)
				}
			}
		}
	}
	for i := range waitsFor {
		slices.Sort(waitsFor[i])
		waitsFor[i] = slices.Compact(waitsFor[i])
	}
	if cycle := findCycle(processors, waitsFor); cycle != "" {
		return nil, fmt.Errorf("processors depend on each other in a cycle: %v", cycle)
	}
	return waitsFor, nil
}

// providedAnywhere reports whether some registered processor of phase
// provides product. When only a subset of processors runs, as in tests or
// for one loader's graph, a need met outside it does not hold anything up.
func providedAnywhere(product Product, phase Phase) bool {
	for _, p := range registeredProcessors {
		if p.Phase <= phase && slices.Contains(p.Provides, product) {
			return true
		}
	}
	return false
}

func findCycle(processors []processorInfo, waitsFor [][]int) string {
	const (
		unvisited = iota
		visiting
		done
	)
	state := make([]int, len(processors))
	var path []int
	var visit func(i int) string
	visit = func(i int) string {
		switch state[i] {
		case visiting:
			start := slices.Index(path, i)
			var names []string
			for _, j := range append(path[start:], i) {
				names = append(names, fmt.Sprintf("%q", processors[j].Description))
			}
			return strings.Join(names, " -> ")
		case done:
			return ""
		}
		state[i] = visiting
		path = append(path, i)
		for _, j := range waitsFor[i] {
			if cycle := visit(j); cycle != "" {
				return cycle
			}
		}
		path = path[:len(path)-1]
		state[i] = done
		return ""
	}
	for i := range processors {
		if cycle := visit(i); cycle != "" {
			return cycle
		}
	}
	return ""
}

// ValidateProcessors checks that every phase of registered processors can
// be ordered: no processor needs a product nobody provides, and there are no
// cycles.
func ValidateProcessors() error {
	for _, phase := range []Phase{BeforeMerge, AfterMerge} {
		if _, err := processorOrder(selectProcessors(AnyLoader, phase, nil), phase); err != nil {
			return fmt.Errorf("%v: %w", phase, err)
		}
	}
	return nil
}

func runProcessors(ao *IndexedGraph, phase Phase, processors []processorInfo) error {
	if len(processors) == 0 {
		return nil
	}
	waitsFor, err := processorOrder(processors, phase)
	if err != nil {
		return err
	}

	aoLen := ao.Order()
	pb := ui.ProgressBar(fmt.Sprintf("Processing %v", phase), int64(len(processors)*aoLen))
	defer pb.Finish()

	finished := make([]bool, len(processors))
	ready := func(i int) bool {
		if finished[i] {
			return false
		}
		for _, j := range waitsFor[i] {
			if !finished[j] {
				return false
			}
		}
		return true
	}

	for remaining := len(processors); remaining > 0; {
		// Everything ready that only reads a frozen view runs together;
		// otherwise the first ready mutator runs alone.
		var batch []int
		mutator := -1
		for i := range processors {
			if !ready(i) {
				continue
			}
			if processors[i].kind == ProcessorKindGraphMutator {
				if mutator < 0 {
					mutator = i
				}
				continue
			}
			batch = append(batch, i)
		}
		switch {
		case len(batch) > 0:
			runFrozenBatch(ao, processors, batch)
		case mutator >= 0:
			ui.Debug().Msgf("Running %v", processors[mutator].Description)
			start := time.Now()
			processors[mutator].mutator(ao)
			recordTiming(processors[mutator], start)
			batch = []int{mutator}
		default:
			return fmt.Errorf("no processor can run, %v are waiting", remaining)
		}
		for _, i := range batch {
			finished[i] = true
			pb.Add(int64(aoLen))
		}
		remaining -= len(batch)
	}
	return nil
}

func runFrozenBatch(ao *IndexedGraph, processors []processorInfo, batch []int) {
	view := ao.Freeze()
	nodePatches := make([]NodePatchSet, len(batch))
	edgeDeltas := make([]EdgeDelta, len(batch))

	var wg sync.WaitGroup
	for n, i := range batch {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := processors[i]
			ui.Debug().Msgf("Running %v", p.Description)
			defer recordTiming(p, time.Now())
			switch p.kind {
			case ProcessorKindReadOnly:
				p.readOnly(view)
			case ProcessorKindNodePatch:
				p.nodePatch(view, &nodePatches[n])
			case ProcessorKindEdgeDelta:
				p.edgeDelta(view, &edgeDeltas[n])
			}
		}()
	}
	wg.Wait()

	var dropIndexes bool
	for n := range nodePatches {
		nodePatches[n].Apply(ao)
		dropIndexes = dropIndexes || nodePatches[n].HasOperations()
	}
	if dropIndexes {
		ao.DropIndexes()
	}
	for n := range edgeDeltas {
		edgeDeltas[n].Apply(ao)
	}
}
