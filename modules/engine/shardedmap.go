package engine

import (
	"hash/maphash"
	"sync"
)

// shardedMap is a concurrent map for many distinct keys written as often as
// read, such as the graph's node lookups while loading. Each shard has its
// own lock, so inserts never copy the map the way sync.Map's promotion does.
type shardedMap[K comparable, V any] struct {
	once   sync.Once
	shards *[shardCount]mapShard[K, V]
}

const shardCount = 256

type mapShard[K comparable, V any] struct {
	sync.RWMutex
	m map[K]V
}

var shardSeed = maphash.MakeSeed()

func (s *shardedMap[K, V]) shard(key K) *mapShard[K, V] {
	s.once.Do(func() {
		s.shards = new([shardCount]mapShard[K, V])
		for i := range s.shards {
			s.shards[i].m = map[K]V{}
		}
	})
	return &s.shards[maphash.Comparable(shardSeed, key)%shardCount]
}

func (s *shardedMap[K, V]) Load(key K) (V, bool) {
	sh := s.shard(key)
	sh.RLock()
	v, found := sh.m[key]
	sh.RUnlock()
	return v, found
}

// LoadOrStore returns the value for key if there is one, and otherwise
// stores value; found reports which.
func (s *shardedMap[K, V]) LoadOrStore(key K, value V) (V, bool) {
	sh := s.shard(key)
	sh.Lock()
	defer sh.Unlock()
	if v, found := sh.m[key]; found {
		return v, true
	}
	sh.m[key] = value
	return value, false
}

func (s *shardedMap[K, V]) Store(key K, value V) {
	sh := s.shard(key)
	sh.Lock()
	sh.m[key] = value
	sh.Unlock()
}

func (s *shardedMap[K, V]) Delete(key K) {
	sh := s.shard(key)
	sh.Lock()
	delete(sh.m, key)
	sh.Unlock()
}
