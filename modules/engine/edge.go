package engine

import (
	"math/bits"
	"strings"
	"sync"
	"sync/atomic"
)

type ProbabilityCalculatorFunction func(source, target *Object) Probability

func (pm Edge) RegisterProbabilityCalculator(doCalc ProbabilityCalculatorFunction) Edge {
	edgeInfos[pm].probability = doCalc
	return pm
}

func (pm Edge) Describe(description string) Edge {
	edgeInfos[pm].Description = description
	return pm
}

func (pm Edge) Probability(source, target *Object) Probability {
	if f := edgeInfos[pm].probability; f != nil {
		return f(source, target)
	}

	// default
	return 100
}

// EdgeAnalyzer takes an Object, examines it an outputs a list of Objects that can Pwn it
type EdgeAnalyzer struct {
	ObjectAnalyzer func(o *Object, ao *Objects)
	Description    string
}

// Increas this when we run out of space
const PMBSIZE = 2
const MAXEDGEPOSSIBLE = PMBSIZE * 64

type EdgeBitmap [PMBSIZE]uint64
type Probability int8

const (
	MINPROBABILITY Probability = -1
	MAXPROBABILITY Probability = 100
)

type EdgeInfo struct {
	Target      *Object
	Edge        Edge
	Probability Probability
}

func (eb EdgeBitmap) Set(edge Edge) EdgeBitmap {
	return eb.set(edge)
}

func (eb *EdgeBitmap) AtomicSet(edge Edge) {
	index, bits := bitIndex(edge)

	for {
		oldvalue := atomic.LoadUint64(&eb[index])
		newvalue := oldvalue | bits
		if atomic.CompareAndSwapUint64(&eb[index], oldvalue, newvalue) {
			// We won the race
			break
		}
	}
}

func (eb *EdgeBitmap) AtomicOr(edges EdgeBitmap) {
	index := 0
	for {
		oldvalue := atomic.LoadUint64(&eb[index])
		newvalue := oldvalue | edges[index]
		if atomic.CompareAndSwapUint64(&eb[index], oldvalue, newvalue) {
			// We won the race
			index++
			if index == PMBSIZE {
				break
			}
		}
	}
}

func (eb EdgeBitmap) set(edge Edge) EdgeBitmap {
	newpm := eb
	index, bits := bitIndex(edge)
	newpm[index] = eb[index] | bits
	return newpm
}

func (eb EdgeBitmap) Clear(edge Edge) EdgeBitmap {
	newpm := eb
	index, bits := bitIndex(edge)
	newpm[index] = eb[index] &^ bits
	return newpm
}

func bitIndex(edge Edge) (int, uint64) {
	return int(edge) >> 6, uint64(1) << (edge & 63)
}

func (eb *EdgeBitmap) AtomicClear(edge Edge) {
	atomic.AddUint64(&EdgePopularity[edge], 1)
	index, bits := bitIndex(edge)

	for {
		oldvalue := atomic.LoadUint64(&eb[index])
		newvalue := oldvalue & ^bits
		if atomic.CompareAndSwapUint64(&eb[index], oldvalue, newvalue) {
			// We won the race
			break
		}
	}
}

func (eb *EdgeBitmap) AtomicAnd(edges EdgeBitmap) {
	index := 0
	for {
		oldvalue := atomic.LoadUint64(&eb[index])
		newvalue := oldvalue & edges[index]
		if atomic.CompareAndSwapUint64(&eb[index], oldvalue, newvalue) {
			// We won the race
			index++
			if index == PMBSIZE {
				break
			}
		}
	}
}

func (eb EdgeBitmap) Invert() EdgeBitmap {
	for index := 0; index <= PMBSIZE; index++ {
		eb[index] = ^eb[index]
	}
	return eb
}

func (eb EdgeBitmap) Intersect(edges EdgeBitmap) EdgeBitmap {
	var new EdgeBitmap
	for i := 0; i < PMBSIZE; i++ {
		new[i] = eb[i] & edges[i]
	}
	return new
}

func (eb EdgeBitmap) Merge(edges EdgeBitmap) EdgeBitmap {
	var new EdgeBitmap
	for i := 0; i < PMBSIZE; i++ {
		new[i] = eb[i] | edges[i]
	}
	return new
}

func (eb EdgeBitmap) Count() int {
	var ones int
	for i := 0; i < PMBSIZE; i++ {
		ones += bits.OnesCount64(uint64(eb[i]))
	}
	return ones
}

func (eb EdgeBitmap) IsBlank() bool {
	for i := 0; i < PMBSIZE; i++ {
		if eb[i] != 0 {
			return false
		}
	}
	return true
}

func (eb EdgeBitmap) Edges() []Edge {
	result := make([]Edge, eb.Count())
	var n int
	for i := 0; i < len(edgeInfos) && n < len(result); i++ {
		if eb.IsSet(Edge(i)) {
			result[n] = Edge(i)
			n++
		}
	}
	return result
}

type Edge int

var edgeMutex sync.RWMutex
var edgeNames = make(map[string]Edge)
var edgeInfos []*edgeInfo

type edgeInfo struct {
	probability                  ProbabilityCalculatorFunction
	Name                         string
	Description                  string
	tags                         []string
	multi                        bool // If true, this attribute can have multiple values
	nonunique                    bool // Doing a Find on this attribute will return multiple results
	merge                        bool // If true, objects can be merged on this attribute
	hidden                       bool // If true, this attribute is not shown in the UI
	defaultf, defaultm, defaultl bool
}

func NewEdge(name string) Edge {
	// Lowercase it, everything is case insensitive
	lowername := strings.ToLower(name)

	edgeMutex.RLock()
	if pwn, found := edgeNames[lowername]; found {
		edgeMutex.RUnlock()
		return pwn
	}
	edgeMutex.RUnlock()
	edgeMutex.Lock()
	// Retry, someone might have beaten us to it
	if pwn, found := edgeNames[lowername]; found {
		edgeMutex.Unlock()
		return pwn
	}

	newindex := Edge(len(edgeInfos))
	if newindex == MAXEDGEPOSSIBLE {
		panic("Too many Edge definitions")
	}

	edgeInfos = append(edgeInfos, &edgeInfo{
		Name:     name,
		defaultf: true,
		defaultm: true,
		defaultl: true,
	})
	edgeNames[lowername] = newindex
	edgeMutex.Unlock()

	return Edge(newindex)
}

func (p Edge) String() string {
	if int(p) >= len(edgeInfos) {
		return "INVALID EDGE"
	}
	return edgeInfos[p].Name
}

func (p Edge) DefaultF() bool {
	return edgeInfos[p].defaultf
}

func (p Edge) DefaultM() bool {
	return edgeInfos[p].defaultm
}

func (p Edge) DefaultL() bool {
	return edgeInfos[p].defaultl
}

func (p Edge) SetDefault(f, m, l bool) Edge {
	edgeMutex.Lock()
	edgeInfos[p].defaultf = f
	edgeInfos[p].defaultm = m
	edgeInfos[p].defaultl = l
	edgeMutex.Unlock()
	return p
}

func (p Edge) Hidden() Edge {
	edgeMutex.Lock()
	edgeInfos[p].hidden = true
	edgeMutex.Unlock()
	return p
}

func (p Edge) IsHidden() bool {
	return edgeInfos[p].hidden
}

func LookupEdge(name string) Edge {
	edgeMutex.RLock()
	defer edgeMutex.RUnlock()
	if pwn, found := edgeNames[strings.ToLower(name)]; found {
		return pwn
	}
	return NonExistingEdgeType
}

func E(name string) Edge {
	return LookupEdge(name)
}

func AllEdgesSlice() []Edge {
	result := make([]Edge, len(edgeInfos))
	edgeMutex.RLock()
	for i := 0; i < len(edgeInfos); i++ {
		result[i] = Edge(i)
	}
	edgeMutex.RUnlock()
	return result
}

var (
	NonExistingEdgeType = Edge(10000)
	AnyEdgeType         = Edge(9999)
)

var AllEdgesBitmap EdgeBitmap

var EdgePopularity [MAXEDGEPOSSIBLE]uint64

func init() {
	for i := Edge(0); i < MAXEDGEPOSSIBLE; i++ {
		AllEdgesBitmap = AllEdgesBitmap.set(i)
	}
}

type EdgeDirection int

const (
	Out EdgeDirection = 0
	In  EdgeDirection = 1
)

func (m EdgeBitmap) IsSet(edge Edge) bool {
	index, bits := bitIndex(edge)
	return (m[index] & bits) != 0
}

func (m EdgeBitmap) MaxProbability(source, target *Object) Probability {
	max := MINPROBABILITY
	for i := 0; i < len(edgeInfos); i++ {
		if m.IsSet(Edge(i)) {
			prob := Edge(i).Probability(source, target)
			if prob == MAXPROBABILITY {
				return prob
			}
			if prob > max {
				max = prob
			}
		}
	}
	return max
}

func (m EdgeBitmap) JoinedString() string {
	var result string
	for i := 0; i < len(edgeInfos); i++ {
		if m.IsSet(Edge(i)) {
			if len(result) != 0 {
				result += ", "
			}
			result += Edge(i).String()
		}
	}
	return result
}

func (m EdgeBitmap) StringSlice() []string {
	result := make([]string, m.Count())
	var current int
	for i := 0; i < len(edgeInfos); i++ {
		if m.IsSet(Edge(i)) {
			result[current] = Edge(i).String()
			current++
		}
	}
	return result
}
