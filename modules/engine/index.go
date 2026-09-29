package engine

import (
	"sync"
)

type Index struct {
	lookup map[AttributeValue]*NodeSlice
	sync.RWMutex
}

func (i *Index) init() {
	i.lookup = make(map[AttributeValue]*NodeSlice)
}

func (i *Index) Lookup(key AttributeValue) (NodeSlice, bool) {
	iv := AttributeValueToIndex(key)
	i.RLock()
	result, found := i.lookup[iv]
	i.RUnlock()
	if !found {
		return NodeSlice{}, false
	}
	return *result, found
}

func (i *Index) Add(key AttributeValue, o *Node, undupe bool) {
	iv := AttributeValueToIndex(key)
	i.Lock()
	existing, found := i.lookup[iv]
	if !found {
		new := NewNodeSlice(0)
		i.lookup[iv] = &new
		existing = &new
	}
	i.Unlock()
	if undupe && existing.Len() > 0 {
		dupefound := false
		existing.Iterate(func(eo *Node) bool {
			if o == eo {
				dupefound = true
				return false
			}
			return true
		})
		if dupefound {
			return
		}
	}
	existing.Add(o)
}

func (i *Index) Iterate(each func(key AttributeValue, objects NodeSlice) bool) {
	i.RLock()
	for key, value := range i.lookup {
		if !each(key, *value) {
			break
		}
	}
	i.RUnlock()
}

type MultiIndex struct {
	lookup map[AttributeValuePair]*NodeSlice
	sync.RWMutex
}

func (i *MultiIndex) init() {
	i.lookup = make(map[AttributeValuePair]*NodeSlice)
}

func (i *MultiIndex) Lookup(key, key2 AttributeValue) (NodeSlice, bool) {
	iv := AttributeValueToIndex(key)
	iv2 := AttributeValueToIndex(key2)

	i.RLock()
	result, found := i.lookup[AttributeValuePair{iv, iv2}]
	i.RUnlock()
	if !found {
		return NodeSlice{}, false
	}
	return *result, found
}

func (i *MultiIndex) Add(key, key2 AttributeValue, o *Node, undupe bool) {
	iv := AttributeValueToIndex(key)
	iv2 := AttributeValueToIndex(key2)
	avp := AttributeValuePair{iv, iv2}
	i.Lock()
	existing, found := i.lookup[avp]
	if !found {
		new := NewNodeSlice(0)
		i.lookup[avp] = &new
		existing = &new
	}
	if undupe && existing.Len() > 0 {
		dupefound := false
		existing.Iterate(func(eo *Node) bool {
			if o == eo {
				dupefound = true
				return false
			}
			return true
		})
		if dupefound {
			i.Unlock()
			return
		}
	}

	existing.Add(o)
	i.Unlock()
}

func (i *MultiIndex) Iterate(each func(key, key2 AttributeValue, objects NodeSlice) bool) {
	i.RLock()
	for pair, value := range i.lookup {
		if !each(pair.Value1, pair.Value2, *value) {
			break
		}
	}
	i.RUnlock()
}
