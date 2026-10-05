package engine

import (
	"cmp"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/adalanche/modules/ui"
)

type ProgressCallbackFunc func(progress int, totalprogress int)

// ProcessorFunc is a processor that reads the graph and writes through a
// transaction, committed when the processors running with it are done.
type ProcessorFunc func(tx *Tx)

// ExclusiveProcessorFunc is a processor that runs alone and needs to see its
// own changes as it goes. It changes the graph only through transactions it
// begins and commits itself.
type ExclusiveProcessorFunc func(g *IndexedGraph)

// Phase says which graph a processor works on.
type Phase int

const (
	// LoaderPhase processors run before loading finishes, each in a
	// transaction that sees only its loader's nodes, as if the loader had a
	// graph of its own.
	LoaderPhase Phase = iota
	// AnalysisPhase processors run once loading has finished (parent claims
	// applied, references resolved), on the whole graph.
	AnalysisPhase
)

func (p Phase) String() string {
	switch p {
	case LoaderPhase:
		return "loader"
	case AnalysisPhase:
		return "analysis"
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

type processorInfo struct {
	Processor
	loader    LoaderID
	tx        ProcessorFunc
	exclusive ExclusiveProcessorFunc
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

// AddProcessor registers a processor that works through a transaction.
// Processors that are ready at the same time run in parallel, and their
// transactions are committed together.
func (l LoaderID) AddProcessor(pf ProcessorFunc, p Processor) {
	registeredProcessors = append(registeredProcessors, processorInfo{Processor: p, loader: l, tx: pf})
}

// AddExclusiveProcessor registers a processor that runs alone.
func (l LoaderID) AddExclusiveProcessor(pf ExclusiveProcessorFunc, p Processor) {
	registeredProcessors = append(registeredProcessors, processorInfo{Processor: p, loader: l, exclusive: pf})
}

// processorSeed orders processors that are free to run at the same time.
// With complete dependencies the result is the same for every seed.
var (
	processorSeedMutex sync.Mutex
	processorSeed      uint64
	processorSeedSet   bool
)

// SetProcessorSeed fixes the order of processors that are free to run at
// the same time, to reproduce a run.
func SetProcessorSeed(seed uint64) {
	processorSeedMutex.Lock()
	processorSeed, processorSeedSet = seed, true
	processorSeedMutex.Unlock()
}

func currentProcessorSeed() uint64 {
	processorSeedMutex.Lock()
	defer processorSeedMutex.Unlock()
	if !processorSeedSet {
		if env := os.Getenv("ADALANCHE_PROCESSOR_SEED"); env != "" {
			if seed, err := strconv.ParseUint(env, 10, 64); err == nil {
				processorSeed, processorSeedSet = seed, true
			}
		}
		if !processorSeedSet {
			processorSeed, processorSeedSet = uint64(time.Now().UnixNano()), true
		}
		ui.Info().Msgf("Processor order seed %v (set ADALANCHE_PROCESSOR_SEED to reproduce)", processorSeed)
	}
	return processorSeed
}

// AnyLoader selects the processors of every loader.
const AnyLoader LoaderID = -1

// RunPhase runs the processors of loader l (or AnyLoader) for phase, each
// after the processors it depends on.
func RunPhase(ao *IndexedGraph, l LoaderID, phase Phase) error {
	return runPhase(ao, l, phase, nil)
}

// runPhase is RunPhase reporting how many processors have finished.
func runPhase(ao *IndexedGraph, l LoaderID, phase Phase, report func(done, total int)) error {
	return runProcessors(ao, phase, selectProcessors(l, phase, nil), report)
}

// RunProviders runs only the processors of loader l (or AnyLoader) for
// phase that provide one of products, in dependency order among
// themselves. It is meant for tests of a few processors.
func RunProviders(ao *IndexedGraph, l LoaderID, phase Phase, products ...Product) error {
	return runProcessors(ao, phase, selectProcessors(l, phase, products), nil)
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
	for _, phase := range []Phase{LoaderPhase, AnalysisPhase} {
		if _, err := processorOrder(selectProcessors(AnyLoader, phase, nil), phase); err != nil {
			return fmt.Errorf("%v: %w", phase, err)
		}
	}
	return nil
}

func runProcessors(ao *IndexedGraph, phase Phase, processors []processorInfo, report func(done, total int)) error {
	if len(processors) == 0 {
		return nil
	}
	waitsFor, err := processorOrder(processors, phase)
	if err != nil {
		return err
	}


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

	random := rand.New(rand.NewPCG(currentProcessorSeed(), uint64(phase)))
	for remaining := len(processors); remaining > 0; {
		// Every ready transaction processor runs together; otherwise one
		// ready exclusive processor runs alone.
		var batch, exclusive []int
		for i := range processors {
			if !ready(i) {
				continue
			}
			if processors[i].exclusive != nil {
				exclusive = append(exclusive, i)
				continue
			}
			batch = append(batch, i)
		}
		switch {
		case len(batch) > 0:
			if err := runBatch(ao, phase, processors, batch, random); err != nil {
				return err
			}
		case len(exclusive) > 0:
			alone := exclusive[random.IntN(len(exclusive))]
			ui.Debug().Msgf("Running %v", processors[alone].Description)
			start := time.Now()
			processors[alone].exclusive(ao)
			recordTiming(processors[alone], start)
			batch = []int{alone}
		default:
			return fmt.Errorf("no processor can run, %v are waiting", remaining)
		}
		for _, i := range batch {
			finished[i] = true
		}
		remaining -= len(batch)
		if report != nil {
			report(len(processors)-remaining, len(processors))
		}
	}
	return nil
}

// runBatch runs transaction processors in parallel. None of them changes
// the graph while they run; their transactions are committed afterwards in
// processor order, so the result does not depend on which finished first.
func runBatch(ao *IndexedGraph, phase Phase, processors []processorInfo, batch []int, random *rand.Rand) error {
	txs := make([]*Tx, len(batch))

	start := slices.Clone(batch)
	random.Shuffle(len(start), func(a, b int) { start[a], start[b] = start[b], start[a] })
	position := map[int]int{}
	for n, i := range batch {
		position[i] = n
	}

	var wg sync.WaitGroup
	for _, i := range start {
		n := position[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := processors[i]
			ui.Debug().Msgf("Running %v", p.Description)
			defer recordTiming(p, time.Now())
			txs[n] = ao.Begin(p.Description)
			if scope := ao.loaderScopes[p.loader]; phase == LoaderPhase && scope != "" {
				// In the loader phase, a loader's processors see its own nodes.
				txs[n].scopeTo(scope)
			}
			p.tx(txs[n])
		}()
	}
	wg.Wait()

	var commits []*Tx
	for _, tx := range txs {
		if tx.HasWrites() {
			commits = append(commits, tx)
		}
	}
	return ao.Commit(commits...)
}
