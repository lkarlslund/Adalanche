package engine

import (
	"math/bits"
	"sort"
	"strings"
	"sync"
)

// PwnAnalyzer takes an Object, examines it an outputs a list of Objects that can Pwn it
type PwnAnalyzer struct {
	ObjectAnalyzer func(o *Object, ao *Objects)
	Description    string
}

const PMBSIZE = 4
const MAXPWNMETHODPOSSIBLE = PMBSIZE * 64

type PwnMethodBitmap [PMBSIZE]uint64
type Probability int8

type PwnInfo struct {
	Target      *Object
	Method      PwnMethod
	Probability Probability
}

func (pm PwnMethodBitmap) Set(method PwnMethod) PwnMethodBitmap {
	PwnPopularity[method]++
	return pm.set(method)
}

func (pm PwnMethodBitmap) set(method PwnMethod) PwnMethodBitmap {
	newpm := pm
	newpm[int(method)/64] = pm[int(method)/64] | 1<<(method%64)
	return newpm
}

func (pm PwnMethodBitmap) Intersect(methods PwnMethodBitmap) PwnMethodBitmap {
	var newpm PwnMethodBitmap
	for i := 0; i < PMBSIZE; i++ {
		newpm[i] = pm[i] & methods[i]
	}
	return newpm
}

func (pm PwnMethodBitmap) Merge(methods PwnMethodBitmap) PwnMethodBitmap {
	var newpm PwnMethodBitmap
	for i := 0; i < PMBSIZE; i++ {
		newpm[i] = pm[i] | methods[i]
	}
	return newpm
}

func (pm PwnMethodBitmap) Count() int {
	var ones int
	for i := 0; i < PMBSIZE; i++ {
		ones += bits.OnesCount64(uint64(pm[i]))
	}
	return ones
}

func (pm PwnMethodBitmap) Methods() []PwnMethod {
	result := make([]PwnMethod, pm.Count())
	var n int
	for i := 0; i < len(pwnnums); i++ {
		if pm.IsSet(PwnMethod(i)) {
			result[n] = PwnMethod(i)
			n++
		}
	}
	return result
}

func (pc PwnConnections) Objects() ObjectSlice {
	result := make(ObjectSlice, len(pc))
	var i int
	for object := range pc {
		result[i] = object
		i++
	}
	sort.Sort(result)
	return result
}

func (pc PwnConnections) Set(o *Object, method PwnMethod) {
	p := pc[o]
	pc[o] = p.Set(method)
}

type PwnMethod int

var pwnmutex sync.RWMutex
var pwnnames = make(map[string]PwnMethod)
var pwnnums []pwninfo

type pwninfo struct {
	name                         string
	tags                         []string
	multi                        bool // If true, this attribute can have multiple values
	nonunique                    bool // Doing a Find on this attribute will return multiple results
	merge                        bool // If true, objects can be merged on this attribute
	defaultf, defaultm, defaultl bool
}

func NewPwn(name string) PwnMethod {
	// Lowercase it, everything is case insensitive
	lowername := strings.ToLower(name)

	pwnmutex.RLock()
	if pwn, found := pwnnames[lowername]; found {
		pwnmutex.RUnlock()
		return pwn
	}
	pwnmutex.RUnlock()
	pwnmutex.Lock()
	// Retry, someone might have beaten us to it
	if pwn, found := pwnnames[lowername]; found {
		pwnmutex.Unlock()
		return pwn
	}

	newindex := PwnMethod(len(pwnnums))
	pwnnums = append(pwnnums, pwninfo{
		name:     name,
		defaultf: true,
		defaultm: true,
		defaultl: true,
	})
	pwnnames[lowername] = newindex
	pwnmutex.Unlock()

	return PwnMethod(newindex)
}

func (p PwnMethod) String() string {
	if p == 10000 {
		return "NOT A PWN METHOD. DIVISION BY ZORRO ERROR."
	}
	return pwnnums[p].name
}

func LookupPwnMethod(name string) PwnMethod {
	pwnmutex.RLock()
	defer pwnmutex.RUnlock()
	if pwn, found := pwnnames[strings.ToLower(name)]; found {
		return pwn
	}
	return NonExistingPwnMethod
}

func P(name string) PwnMethod {
	return LookupPwnMethod(name)
}

func AllPwnMethodsSlice() []PwnMethod {
	result := make([]PwnMethod, len(pwnnums))
	pwnmutex.RLock()
	for i := 0; i < len(pwnnums); i++ {
		result[i] = PwnMethod(i)
	}
	pwnmutex.RUnlock()
	return result
}

var (
	NonExistingPwnMethod = PwnMethod(10000)
	AnyPwnMethod         = PwnMethod(9999)
)

var AllPwnMethods PwnMethodBitmap

var PwnPopularity [PMBSIZE * 64]uint64

func init() {
	for i := PwnMethod(0); i < PMBSIZE*64; i++ {
		AllPwnMethods = AllPwnMethods.set(i)
	}
}

/*
type PwnMethodsAndProbabilities struct {
	PwnMethodBitmap                 // Indicates if we have this method registered
	probabilitymap  PwnMethodBitmap // Indicates if we have a probability set or should just return 100
	probabilities   Probabilities
}
*/

type PwnConnections map[*Object]PwnMethodBitmap //sAndProbabilities

func (m PwnMethodBitmap) IsSet(method PwnMethod) bool {
	return (m[method/64] & (1 << (method % 64))) != 0 // Uuuuh, nasty and unreadable
}

func (m PwnMethodBitmap) MaxProbabiltity(source, target *Object) Probability {
	var max Probability
	for i := 0; i < len(pwnnums); i++ {
		if m.IsSet(PwnMethod(i)) {
			prob := CalculateProbability(source, target, PwnMethod(i))
			if prob == 100 {
				return prob
			}
			if prob > max {
				max = prob
			}
		}
	}
	return max
}

func (m PwnMethodBitmap) JoinedString() string {
	var result string
	for i := 0; i < len(pwnnums); i++ {
		if m.IsSet(PwnMethod(i)) {
			if len(result) != 0 {
				result += ", "
			}
			result += PwnMethod(i).String()
		}
	}
	return result
}

func (m PwnMethodBitmap) StringSlice() []string {
	var result []string
	for i := 0; i < len(pwnnums); i++ {
		if m.IsSet(PwnMethod(i)) {
			result = append(result, PwnMethod(i).String())
		}
	}
	return result
}

func (m PwnMethodBitmap) StringBoolMap() map[string]bool {
	var result = make(map[string]bool)
	for i := 0; i < len(pwnnums); i++ {
		if m.IsSet(PwnMethod(i)) {
			result["pwn_"+PwnMethod(i).String()] = true
		}
	}
	return result
}
