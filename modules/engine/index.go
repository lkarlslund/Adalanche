package engine

import (
	"hash/maphash"
	"slices"
	"strings"
	"sync"
)

// Indexes are keyed by a 64-bit hash of the value. Strings hash under simple
// case folding, so values that compare equal ignoring case share a hash; all
// other kinds hash their exact value. The hash only selects a bucket: every
// entry keeps its key and is matched with indexKeyEqual, so a collision
// costs a comparison, never a wrong result. The hash is seeded per process,
// so which values collide cannot be planned.

var indexSeed = maphash.MakeSeed()

// indexHash is a variable so tests can force collisions.
var indexHash = func(v AttributeValue) uint64 {
	if v.kind == kindString {
		return stringTable.foldHash(uint32(v.bits))
	}
	return maphash.Comparable(indexSeed, v)
}

func indexKeyEqual(a, b AttributeValue) bool {
	if a == b {
		return true
	}
	if a.kind == kindString && b.kind == kindString {
		return strings.EqualFold(stringTable.get(uint32(a.bits)), stringTable.get(uint32(b.bits)))
	}
	return false
}

func containsNode(ns NodeSlice, o *Node) bool {
	return slices.Contains(ns.nodes, o)
}

type indexEntry struct {
	key   AttributeValue
	nodes NodeSlice
	next  *indexEntry // another key with the same hash
}

type Index struct {
	lookup map[uint64]*indexEntry
	sync.RWMutex
}

func (i *Index) init() {
	i.lookup = make(map[uint64]*indexEntry)
}

func (i *Index) find(key AttributeValue, hash uint64) *indexEntry {
	for e := i.lookup[hash]; e != nil; e = e.next {
		if indexKeyEqual(e.key, key) {
			return e
		}
	}
	return nil
}

func (i *Index) Lookup(key AttributeValue) (NodeSlice, bool) {
	hash := indexHash(key)
	i.RLock()
	e := i.find(key, hash)
	var result NodeSlice
	if e != nil {
		result = e.nodes
	}
	i.RUnlock()
	return result, e != nil
}

func (i *Index) Add(key AttributeValue, o *Node, undupe bool) {
	hash := indexHash(key)
	i.Lock()
	defer i.Unlock()
	e := i.find(key, hash)
	if e == nil {
		e = &indexEntry{key: key, nodes: NewNodeSlice(0), next: i.lookup[hash]}
		i.lookup[hash] = e
	}
	if undupe && containsNode(e.nodes, o) {
		return
	}
	e.nodes.Add(o)
}

// Iterate visits each distinct key (the first value added for it) and its nodes.
func (i *Index) Iterate(each func(key AttributeValue, objects NodeSlice) bool) {
	i.RLock()
	defer i.RUnlock()
	for _, e := range i.lookup {
		for ; e != nil; e = e.next {
			if !each(e.key, e.nodes) {
				return
			}
		}
	}
}

type multiIndexEntry struct {
	key, key2 AttributeValue
	nodes     NodeSlice
	next      *multiIndexEntry
}

type MultiIndex struct {
	lookup map[uint64]*multiIndexEntry
	sync.RWMutex
}

func (i *MultiIndex) init() {
	i.lookup = make(map[uint64]*multiIndexEntry)
}

func multiIndexHash(key, key2 AttributeValue) uint64 {
	return maphash.Comparable(indexSeed, [2]uint64{indexHash(key), indexHash(key2)})
}

func (i *MultiIndex) find(key, key2 AttributeValue, hash uint64) *multiIndexEntry {
	for e := i.lookup[hash]; e != nil; e = e.next {
		if indexKeyEqual(e.key, key) && indexKeyEqual(e.key2, key2) {
			return e
		}
	}
	return nil
}

func (i *MultiIndex) Lookup(key, key2 AttributeValue) (NodeSlice, bool) {
	hash := multiIndexHash(key, key2)
	i.RLock()
	e := i.find(key, key2, hash)
	var result NodeSlice
	if e != nil {
		result = e.nodes
	}
	i.RUnlock()
	return result, e != nil
}

func (i *MultiIndex) Add(key, key2 AttributeValue, o *Node, undupe bool) {
	hash := multiIndexHash(key, key2)
	i.Lock()
	defer i.Unlock()
	e := i.find(key, key2, hash)
	if e == nil {
		e = &multiIndexEntry{key: key, key2: key2, nodes: NewNodeSlice(0), next: i.lookup[hash]}
		i.lookup[hash] = e
	}
	if undupe && containsNode(e.nodes, o) {
		return
	}
	e.nodes.Add(o)
}

func (i *MultiIndex) Iterate(each func(key, key2 AttributeValue, objects NodeSlice) bool) {
	i.RLock()
	defer i.RUnlock()
	for _, e := range i.lookup {
		for ; e != nil; e = e.next {
			if !each(e.key, e.key2, e.nodes) {
				return
			}
		}
	}
}
