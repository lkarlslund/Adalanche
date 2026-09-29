package engine

import (
	"fmt"
	"math/bits"
	"slices"
	"sync/atomic"
)

// Immutable after publication. Sparse sets store sorted target IDs; dense sets
// store only the word interval containing targets. Empty/singleton sets allocate nothing.
type impactSet struct {
	sparse []uint32
	words  []uint64
	start  uint32 // dense word offset, or singleton target ID
	count  uint32
}

func (s impactSet) contains(id uint32) bool {
	if s.count == 1 {
		return s.start == id
	}
	if s.words != nil {
		word := id / 64
		return word >= s.start && uint64(word-s.start) < uint64(len(s.words)) && s.words[word-s.start]&(uint64(1)<<(id%64)) != 0
	}
	_, found := slices.BinarySearch(s.sparse, id)
	return found
}

type impactSetBuilder struct {
	words   []uint64
	touched []uint32
}

func newImpactSetBuilder(targets uint32) impactSetBuilder {
	return impactSetBuilder{words: make([]uint64, (uint64(targets)+63)/64)}
}

func (b *impactSetBuilder) addWord(index uint32, word uint64) {
	if word == 0 {
		return
	}
	if b.words[index] == 0 {
		b.touched = append(b.touched, index)
	}
	b.words[index] |= word
}

func (b *impactSetBuilder) union(set impactSet) {
	if set.count == 1 {
		b.addWord(set.start/64, uint64(1)<<(set.start%64))
	} else if set.words != nil {
		for i, word := range set.words {
			b.addWord(set.start+uint32(i), word)
		}
	} else {
		for _, target := range set.sparse {
			b.addWord(target/64, uint64(1)<<(target%64))
		}
	}
}

func (b *impactSetBuilder) reset() {
	for _, index := range b.touched {
		b.words[index] = 0
	}
	b.touched = b.touched[:0]
}

// measure adds category counts without allocating an immutable copy of the set.
func (b *impactSetBuilder) measure(boundaries []uint32, counts []uint32) (cardinality, first, last uint32) {
	if len(b.touched) == 0 {
		return 0, 0, 0
	}
	first, last = b.touched[0], b.touched[0]
	for _, index := range b.touched {
		first, last = min(first, index), max(last, index)
		word := b.words[index]
		cardinality += uint32(bits.OnesCount64(word))
		// Category target IDs occupy disjoint contiguous intervals.
		wordStart := uint64(index) * 64
		for category := range counts {
			lo := max(wordStart, uint64(boundaries[category]))
			hi := min(wordStart+64, uint64(boundaries[category+1]))
			if lo < hi {
				mask := ^uint64(0) << (lo - wordStart)
				if hi-wordStart < 64 {
					mask &= (uint64(1) << (hi - wordStart)) - 1
				}
				counts[category] += uint32(bits.OnesCount64(word & mask))
			}
		}
	}
	return cardinality, first, last
}

func (b *impactSetBuilder) finish(largest impactSet, boundaries []uint32, counts []uint32, allocated *atomic.Uint64, limit uint64) (impactSet, error) {
	defer b.reset()
	cardinality, first, last := b.measure(boundaries, counts)
	if cardinality == largest.count {
		// The union contains largest, so equal cardinality proves equal membership.
		return largest, nil
	}
	if cardinality == 1 {
		return impactSet{start: first*64 + uint32(bits.TrailingZeros64(b.words[first])), count: 1}, nil
	}
	denseBytes := (uint64(last) - uint64(first) + 1) * 8
	sparseBytes := uint64(cardinality) * 4
	bytes := min(denseBytes, sparseBytes)
	for {
		previous := allocated.Load()
		if limit != 0 && (bytes > limit || previous > limit-bytes) {
			return impactSet{}, fmt.Errorf("impact target sets exceed the %d-byte budget", limit)
		}
		if allocated.CompareAndSwap(previous, previous+bytes) {
			break
		}
	}
	set := impactSet{count: cardinality}
	if denseBytes <= sparseBytes {
		set.start = first
		set.words = slices.Clone(b.words[first : last+1])
	} else {
		slices.Sort(b.touched)
		set.sparse = make([]uint32, 0, cardinality)
		for _, index := range b.touched {
			for word := b.words[index]; word != 0; word &= word - 1 {
				set.sparse = append(set.sparse, index*64+uint32(bits.TrailingZeros64(word)))
			}
		}
	}
	return set, nil
}
