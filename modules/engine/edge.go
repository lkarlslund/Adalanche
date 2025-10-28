package engine

import (
	"errors"
	"math/bits"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	ErrTooManyEdges = errors.New("too many edges in string slice")
	ErrEdgeNotFound = errors.New("edge not found")
)

type ProbabilityCalculatorFunction func(source, target *Node, edge *EdgeBitmap) Probability
type DetailFunction func(source, target *Node, edge *EdgeBitmap) string

func (pm Edge) RegisterProbabilityCalculator(doCalc ProbabilityCalculatorFunction) Edge {
	edgeInfos[pm].probability = doCalc
	return pm
}

func (pm Edge) Describe(description string) Edge {
	edgeInfos[pm].Description = description
	return pm
}

func (pm Edge) RegisterDetailFunction(doDetails DetailFunction) Edge {
	edgeInfos[pm].detailer = doDetails
	return pm
}

func (pm Edge) Probability(source, target *Node, edges *EdgeBitmap) Probability {
	if f := edgeInfos[pm].probability; f != nil {
		return f(source, target, edges)
	}

	// default
	return 100
}

// EdgeAnalyzer takes an Object, examines it an outputs a list of Objects that can Pwn it
type EdgeAnalyzer struct {
	ObjectAnalyzer func(o *Node, ao *IndexedGraph)
	Description    string
}

// Increas this when we run out of space
const PMBSIZE = 3
const MAXEDGEPOSSIBLE = PMBSIZE * 64

type EdgeBitmap [PMBSIZE]uint64
type Probability int8

const (
	MINPROBABILITY Probability = -1
	MAXPROBABILITY Probability = 100
)

func EdgeBitmapFromStringSlice(edgenames []string) (eb EdgeBitmap, err error) {
	if len(edgenames) > MAXEDGEPOSSIBLE {
		err = ErrTooManyEdges
		return
	}
	for _, edgename := range edgenames {
		edge := LookupEdge(edgename)
		if edge == NonExistingEdge {
			err = ErrEdgeNotFound
			return
		}
		eb = eb.Set(edge)
	}
	return
}

func (eb EdgeBitmap) ToStringSlice() []string {
	edgenames := make([]string, 0, MAXEDGEPOSSIBLE)
	for i := range MAXEDGEPOSSIBLE {
		if eb.IsSet(Edge(i)) {
			edgenames = append(edgenames, Edge(i).String())
		}
	}
	return edgenames
}

func (eb EdgeBitmap) Range(f func(e Edge) bool) {
	for index := range MAXEDGEPOSSIBLE {
		if eb.IsSet(Edge(index)) {
			if !f(Edge(index)) {
				return
			}
		}
	}
}

func (eb EdgeBitmap) Set(edge Edge) EdgeBitmap {
	if !eb.IsSet(edge) {
		atomic.AddUint64(&EdgePopularity[edge], 1)
	}
	return eb.set(edge)
}

func (eb *EdgeBitmap) AtomicSet(edge Edge) {
	if !eb.IsSet(edge) {
		atomic.AddUint64(&EdgePopularity[edge], 1)
	}

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
	index := len(eb) - 1
	for {
		oldvalue := atomic.LoadUint64(&eb[index])
		newvalue := oldvalue | edges[index]
		if atomic.CompareAndSwapUint64(&eb[index], oldvalue, newvalue) {
			// We won the race
			if index == 0 {
				break
			}
			index--
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
	atomic.AddUint64(&EdgePopularity[edge], ^uint64(0))

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

func (eb *EdgeBitmap) PartialAtomicLoad() (edges EdgeBitmap) {
	index := 0
	for {
		edges[index] = atomic.LoadUint64(&eb[index])
		index++
		if index == PMBSIZE {
			break
		}
	}
	return edges
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
	for index := range eb {
		eb[index] = ^eb[index]
	}
	return eb
}

func (eb EdgeBitmap) Intersect(edges EdgeBitmap) EdgeBitmap {
	var new EdgeBitmap
	for i := range new {
		new[i] = eb[i] & edges[i]
	}
	return new
}

func (eb EdgeBitmap) Merge(edges EdgeBitmap) EdgeBitmap {
	var new EdgeBitmap
	for i := range new {
		new[i] = eb[i] | edges[i]
	}
	return new
}

func (eb EdgeBitmap) Count() int {
	var ones int
	for i := range eb {
		ones += bits.OnesCount64(uint64(eb[i]))
	}
	return ones
}

func (eb EdgeBitmap) IsBlank() bool {
	for i := range eb {
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

type Edge byte

type BulkEdgeRequest struct {
	From       NodeIndex
	To         NodeIndex
	EdgeBitmap EdgeBitmap
	Edge       Edge
	Merge      bool
	Clear      bool
}

var edgeMutex sync.RWMutex
var edgeNames = make(map[string]Edge)
var edgeInfos []*edgeInfo

type edgeInfo struct {
	Tags                         map[string]struct{}
	probability                  ProbabilityCalculatorFunction
	detailer                     DetailFunction
	Name                         string
	Description                  string
	Multi                        bool // If true, this attribute can have multiple values
	Nonunique                    bool // Doing a Find on this attribute will return multiple results
	Merge                        bool // If true, objects can be merged on this attribute
	Hidden                       bool // If true, this attribute is not shown in the UI
	DefaultF, DefaultM, DefaultL bool
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
		DefaultF: true,
		DefaultM: true,
		DefaultL: true,
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
	return edgeInfos[p].DefaultF
}

func (p Edge) DefaultM() bool {
	return edgeInfos[p].DefaultM
}

func (p Edge) DefaultL() bool {
	return edgeInfos[p].DefaultL
}

func (p Edge) SetDefault(f, m, l bool) Edge {
	edgeMutex.Lock()
	edgeInfos[p].DefaultF = f
	edgeInfos[p].DefaultM = m
	edgeInfos[p].DefaultL = l
	edgeMutex.Unlock()
	return p
}

func (p Edge) Hidden() Edge {
	edgeMutex.Lock()
	edgeInfos[p].Hidden = true
	edgeMutex.Unlock()
	return p
}

func (p Edge) IsHidden() bool {
	return edgeInfos[p].Hidden
}

func (p Edge) Tag(t string) Edge {
	tags := edgeInfos[p].Tags
	if tags == nil {
		tags = make(map[string]struct{})
		edgeInfos[p].Tags = tags
	}
	tags[t] = struct{}{}
	return p
}

func (p Edge) HasTag(t string) bool {
	_, found := edgeInfos[p].Tags[t]
	return found
}

func LookupEdge(name string) Edge {
	edgeMutex.RLock()
	defer edgeMutex.RUnlock()
	if pwn, found := edgeNames[strings.ToLower(name)]; found {
		return pwn
	}
	return NonExistingEdge
}

func Edges() []Edge {
	result := make([]Edge, len(edgeInfos))
	edgeMutex.RLock()
	for i := 0; i < len(edgeInfos); i++ {
		result[i] = Edge(i)
	}
	edgeMutex.RUnlock()
	return result
}

func EdgeInfos() []edgeInfo {
	result := make([]edgeInfo, len(edgeInfos))
	edgeMutex.RLock()
	for i := 0; i < len(edgeInfos); i++ {
		result[i] = *edgeInfos[i]
	}
	edgeMutex.RUnlock()
	return result
}

var (
	NonExistingEdge = Edge(255)
	AnyEdgeType     = Edge(254)
)

var AllEdgesBitmap EdgeBitmap

var EdgePopularity [MAXEDGEPOSSIBLE]uint64

func init() {
	for i := range Edge(MAXEDGEPOSSIBLE) {
		AllEdgesBitmap = AllEdgesBitmap.set(i)
	}
}

func (m *EdgeBitmap) IsSet(edge Edge) bool {
	index, bits := bitIndex(edge)
	return (atomic.LoadUint64(&m[index]) & bits) != 0
}

func (m *EdgeBitmap) MaxProbability(source, target *Node) Probability {
	max := MINPROBABILITY
	for i := 0; i < len(edgeInfos); i++ {
		if m.IsSet(Edge(i)) {
			prob := Edge(i).Probability(source, target, m)
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
