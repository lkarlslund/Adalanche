package engine

import (
	"hash/maphash"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	xxhash "github.com/cespare/xxhash/v2"
	"github.com/gofrs/uuid/v5"
)

// Process-wide, append-only tables that AttributeValue handles point into.
// Entries are never removed, so handles stay valid for the life of the process.
var (
	stringTable = newStringInterner()
	guidTable   = newInterner[uuid.UUID]()
	nodeTable   = newInterner[*Node]()
	sdTable     = newInterner[*SecurityDescriptor]()
	timeTable   = newInterner[time.Time]() // times that do not fit the inline form
)

const (
	tableChunkBits = 12
	tableChunkSize = 1 << tableChunkBits
)

// chunkedTable stores entries in fixed-size chunks that never move, so reads
// need no lock: a handle is only handed out after its entry is written, and
// the chunk directory is published atomically.
type chunkedTable[T any] struct {
	mu        sync.Mutex
	directory atomic.Pointer[[]*[tableChunkSize]T]
	count     uint32
}

func newChunkedTable[T any]() *chunkedTable[T] {
	t := &chunkedTable[T]{}
	t.directory.Store(&[]*[tableChunkSize]T{})
	return t
}

// add appends v and returns its handle. Callers must hold no table lock.
func (t *chunkedTable[T]) add(v T) uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.addLocked(v)
}

func (t *chunkedTable[T]) addLocked(v T) uint32 {
	index := t.count
	if index == ^uint32(0) {
		panic("attribute value table full")
	}
	chunks := *t.directory.Load()
	if int(index>>tableChunkBits) == len(chunks) {
		grown := make([]*[tableChunkSize]T, len(chunks), len(chunks)+1)
		copy(grown, chunks)
		grown = append(grown, new([tableChunkSize]T))
		t.directory.Store(&grown)
		chunks = grown
	}
	chunks[index>>tableChunkBits][index&(tableChunkSize-1)] = v
	t.count++
	return index
}

func (t *chunkedTable[T]) get(index uint32) T {
	return *t.at(index)
}

// at returns the stored entry; fields written after publication must be
// accessed atomically.
func (t *chunkedTable[T]) at(index uint32) *T {
	return &(*t.directory.Load())[index>>tableChunkBits][index&(tableChunkSize-1)]
}

func (t *chunkedTable[T]) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return int(t.count)
}

// snapshot copies the current entries.
func (t *chunkedTable[T]) snapshot() []T {
	t.mu.Lock()
	defer t.mu.Unlock()
	chunks := *t.directory.Load()
	out := make([]T, t.count)
	for i := range out {
		out[i] = chunks[i>>tableChunkBits][i&(tableChunkSize-1)]
	}
	return out
}

// interner deduplicates comparable values.
type interner[T comparable] struct {
	table   *chunkedTable[T]
	lookup  sync.Map // T -> uint32; read-mostly after loading
	writeMu sync.Mutex
}

func newInterner[T comparable]() *interner[T] {
	return &interner[T]{table: newChunkedTable[T]()}
}

func (in *interner[T]) intern(v T) uint32 {
	if index, found := in.lookup.Load(v); found {
		return index.(uint32)
	}
	in.writeMu.Lock()
	defer in.writeMu.Unlock()
	if index, found := in.lookup.Load(v); found {
		return index.(uint32)
	}
	index := in.table.add(v)
	in.lookup.Store(v, index)
	return index
}

func (in *interner[T]) get(index uint32) T {
	return in.table.get(index)
}

// stringInterner keys its lookup by a 64-bit hash, so the lookup holds no
// string pointers for the collector to scan. Hash collisions are checked
// against the stored string and resolved in a small overflow map.
type stringEntry struct {
	s    string
	fold uint64 // hash under simple case folding, for case-insensitive indexes
}

type stringInterner struct {
	table    *chunkedTable[stringEntry]
	shards   [64]stringShard
	overflow sync.Map // string -> uint32, only for hash collisions
}

type stringShard struct {
	mu     sync.RWMutex
	lookup map[uint64]uint32
}

func newStringInterner() *stringInterner {
	s := &stringInterner{table: newChunkedTable[stringEntry]()}
	for i := range s.shards {
		s.shards[i].lookup = map[uint64]uint32{}
	}
	return s
}

func (s *stringInterner) intern(v string) uint32 {
	hash := xxhash.Sum64String(v)
	shard := &s.shards[hash%uint64(len(s.shards))]

	shard.mu.RLock()
	index, found := shard.lookup[hash]
	shard.mu.RUnlock()
	if found {
		if s.get(index) == v {
			return index
		}
		return s.internCollision(v)
	}

	shard.mu.Lock()
	defer shard.mu.Unlock()
	if index, found := shard.lookup[hash]; found {
		if s.get(index) == v {
			return index
		}
		return s.internCollision(v)
	}
	index = s.add(v)
	shard.lookup[hash] = index
	return index
}

func (s *stringInterner) add(v string) uint32 {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()
	index := s.table.count
	if index == ^uint32(0) {
		panic("attribute value table full")
	}
	chunks := *s.table.directory.Load()
	if int(index>>tableChunkBits) == len(chunks) {
		grown := make([]*[tableChunkSize]stringEntry, len(chunks), len(chunks)+1)
		copy(grown, chunks)
		grown = append(grown, new([tableChunkSize]stringEntry))
		s.table.directory.Store(&grown)
		chunks = grown
	}
	chunks[index>>tableChunkBits][index&(tableChunkSize-1)] = stringEntry{s: v, fold: foldHash(v)}
	s.table.count++
	return index
}

func (s *stringInterner) internCollision(v string) uint32 {
	if index, found := s.overflow.Load(v); found {
		return index.(uint32)
	}
	index := s.add(v)
	actual, _ := s.overflow.LoadOrStore(v, index)
	return actual.(uint32)
}

func (s *stringInterner) get(index uint32) string {
	return s.table.at(index).s
}

func (s *stringInterner) foldHash(index uint32) uint64 {
	return s.table.at(index).fold
}

// foldHash hashes s under simple Unicode case folding, the equivalence
// strings.EqualFold uses: each rune is replaced by the smallest rune in its
// folding orbit, so EqualFold(a, b) implies foldHash(a) == foldHash(b).
func foldHash(s string) uint64 {
	var h maphash.Hash
	h.SetSeed(indexSeed)
	var buf [utf8.UTFMax]byte
	for _, r := range s {
		if r < utf8.RuneSelf {
			c := byte(r)
			if 'a' <= c && c <= 'z' {
				c -= 'a' - 'A' // Uppercase is the smallest rune of an ASCII letter's orbit.
			}
			h.WriteByte(c)
			continue
		}
		folded := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			folded = min(folded, f)
		}
		h.Write(buf[:utf8.EncodeRune(buf[:], folded)])
	}
	return h.Sum64()
}
