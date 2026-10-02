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

// indexNodes are the nodes under one index key. Keys such as a loader name
// hold millions of nodes, so membership goes through a set once the list is
// long.
type indexNodes struct {
	nodes   NodeSlice
	members map[*Node]struct{}
}

const indexMembersFrom = 64

func (e *indexNodes) contains(o *Node) bool {
	if e.members != nil {
		_, found := e.members[o]
		return found
	}
	return slices.Contains(e.nodes.nodes, o)
}

func (e *indexNodes) add(o *Node, undupe bool) {
	if undupe && e.contains(o) {
		return
	}
	e.nodes.Add(o)
	if e.members != nil {
		e.members[o] = struct{}{}
	} else if e.nodes.Len() >= indexMembersFrom {
		e.members = make(map[*Node]struct{}, e.nodes.Len()*2)
		for _, n := range e.nodes.nodes {
			e.members[n] = struct{}{}
		}
	}
}

func (e *indexNodes) remove(o *Node) {
	if !e.contains(o) {
		return
	}
	e.nodes.Remove(o)
	if e.members != nil {
		delete(e.members, o)
	}
}

// removeAll takes the given nodes out, keeping the order of the rest.
func (e *indexNodes) removeAll(gone map[*Node]*Node) {
	kept := e.nodes.nodes[:0]
	for _, n := range e.nodes.nodes {
		if _, isGone := gone[n]; isGone {
			if e.members != nil {
				delete(e.members, n)
			}
			continue
		}
		kept = append(kept, n)
	}
	clear(e.nodes.nodes[len(kept):])
	e.nodes.nodes = kept
}

type indexEntry struct {
	key AttributeValue
	indexNodes
	next *indexEntry // another key with the same hash
}

// indexShardCount splits an index by key hash, each part with its own lock,
// so lookups and builds on several workers do not queue on one lock.
const indexShardCount = 64

func indexShardOf(hash uint64) int { return int(hash >> 58) }

type Index struct {
	shards [indexShardCount]indexShard
}

type indexShard struct {
	sync.RWMutex
	lookup map[uint64]*indexEntry
}

// init empties the index; shards make their maps on first use.
func (i *Index) init() {
	for s := range i.shards {
		i.shards[s].lookup = nil
	}
}

func (sh *indexShard) find(key AttributeValue, hash uint64) *indexEntry {
	for e := sh.lookup[hash]; e != nil; e = e.next {
		if indexKeyEqual(e.key, key) {
			return e
		}
	}
	return nil
}

// entry returns the entry for key, adding it if missing. The caller holds
// the shard's lock.
func (sh *indexShard) entry(key AttributeValue, hash uint64) *indexEntry {
	e := sh.find(key, hash)
	if e == nil {
		if sh.lookup == nil {
			sh.lookup = map[uint64]*indexEntry{}
		}
		e = &indexEntry{key: key, next: sh.lookup[hash]}
		sh.lookup[hash] = e
	}
	return e
}

func (i *Index) Lookup(key AttributeValue) (NodeSlice, bool) {
	hash := indexHash(key)
	sh := &i.shards[indexShardOf(hash)]
	sh.RLock()
	e := sh.find(key, hash)
	var result NodeSlice
	if e != nil {
		result = e.nodes
	}
	sh.RUnlock()
	return result, e != nil
}

func (i *Index) Add(key AttributeValue, o *Node, undupe bool) {
	hash := indexHash(key)
	sh := &i.shards[indexShardOf(hash)]
	sh.Lock()
	sh.entry(key, hash).add(o, undupe)
	sh.Unlock()
}

// Remove takes a node off a key, if it is there.
func (i *Index) Remove(key AttributeValue, o *Node) {
	hash := indexHash(key)
	sh := &i.shards[indexShardOf(hash)]
	sh.Lock()
	if e := sh.find(key, hash); e != nil {
		e.remove(o)
	}
	sh.Unlock()
}

// Iterate visits each distinct key (the first value added for it) and its nodes.
func (i *Index) Iterate(each func(key AttributeValue, objects NodeSlice) bool) {
	for s := range i.shards {
		sh := &i.shards[s]
		sh.RLock()
		for _, e := range sh.lookup {
			for ; e != nil; e = e.next {
				if !each(e.key, e.nodes) {
					sh.RUnlock()
					return
				}
			}
		}
		sh.RUnlock()
	}
}

// eachEntry visits every entry's nodes; the caller keeps the index from
// changing meanwhile.
func (i *Index) eachEntry(each func(*indexNodes)) {
	for s := range i.shards {
		for _, e := range i.shards[s].lookup {
			for ; e != nil; e = e.next {
				each(&e.indexNodes)
			}
		}
	}
}

type multiIndexEntry struct {
	key, key2 AttributeValue
	indexNodes
	next *multiIndexEntry
}

type MultiIndex struct {
	shards [indexShardCount]multiIndexShard
}

type multiIndexShard struct {
	sync.RWMutex
	lookup map[uint64]*multiIndexEntry
}

func (i *MultiIndex) init() {
	for s := range i.shards {
		i.shards[s].lookup = nil
	}
}

func multiIndexHash(key, key2 AttributeValue) uint64 {
	return maphash.Comparable(indexSeed, [2]uint64{indexHash(key), indexHash(key2)})
}

func (sh *multiIndexShard) find(key, key2 AttributeValue, hash uint64) *multiIndexEntry {
	for e := sh.lookup[hash]; e != nil; e = e.next {
		if indexKeyEqual(e.key, key) && indexKeyEqual(e.key2, key2) {
			return e
		}
	}
	return nil
}

func (sh *multiIndexShard) entry(key, key2 AttributeValue, hash uint64) *multiIndexEntry {
	e := sh.find(key, key2, hash)
	if e == nil {
		if sh.lookup == nil {
			sh.lookup = map[uint64]*multiIndexEntry{}
		}
		e = &multiIndexEntry{key: key, key2: key2, next: sh.lookup[hash]}
		sh.lookup[hash] = e
	}
	return e
}

func (i *MultiIndex) Lookup(key, key2 AttributeValue) (NodeSlice, bool) {
	hash := multiIndexHash(key, key2)
	sh := &i.shards[indexShardOf(hash)]
	sh.RLock()
	e := sh.find(key, key2, hash)
	var result NodeSlice
	if e != nil {
		result = e.nodes
	}
	sh.RUnlock()
	return result, e != nil
}

func (i *MultiIndex) Add(key, key2 AttributeValue, o *Node, undupe bool) {
	hash := multiIndexHash(key, key2)
	sh := &i.shards[indexShardOf(hash)]
	sh.Lock()
	sh.entry(key, key2, hash).add(o, undupe)
	sh.Unlock()
}

// Remove takes a node off a key pair, if it is there.
func (i *MultiIndex) Remove(key, key2 AttributeValue, o *Node) {
	hash := multiIndexHash(key, key2)
	sh := &i.shards[indexShardOf(hash)]
	sh.Lock()
	if e := sh.find(key, key2, hash); e != nil {
		e.remove(o)
	}
	sh.Unlock()
}

func (i *MultiIndex) Iterate(each func(key, key2 AttributeValue, objects NodeSlice) bool) {
	for s := range i.shards {
		sh := &i.shards[s]
		sh.RLock()
		for _, e := range sh.lookup {
			for ; e != nil; e = e.next {
				if !each(e.key, e.key2, e.nodes) {
					sh.RUnlock()
					return
				}
			}
		}
		sh.RUnlock()
	}
}

func (i *MultiIndex) eachEntry(each func(*indexNodes)) {
	for s := range i.shards {
		for _, e := range i.shards[s].lookup {
			for ; e != nil; e = e.next {
				each(&e.indexNodes)
			}
		}
	}
}
