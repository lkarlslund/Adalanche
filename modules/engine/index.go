package engine

import (
	"sync"
)

type Index struct {
	lookup map[AttributeValue]*ObjectSlice
	sync.RWMutex
}

func (i *Index) init() {
	i.lookup = make(map[AttributeValue]*ObjectSlice)
}

func (i *Index) Lookup(key AttributeValue) (ObjectSlice, bool) {
	iv := AttributeValueToIndex(key)
	i.RLock()
	result, found := i.lookup[iv]
	i.RUnlock()
	if !found {
		return ObjectSlice{}, false
	}
	return *result, found
}

func (i *Index) Add(key AttributeValue, o *Object, undupe bool) {
	iv := AttributeValueToIndex(key)
	i.Lock()
	existing, found := i.lookup[iv]
	if !found {
		new := NewObjectSlice(0)
		i.lookup[iv] = &new
		existing = &new
	}
	i.Unlock()
	if undupe && existing.Len() > 0 {
		dupefound := false
		existing.Iterate(func(eo *Object) bool {
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

func (i *Index) Iterate(each func(key AttributeValue, objects ObjectSlice) bool) {
	i.RLock()
	for key, value := range i.lookup {
		if !each(key, *value) {
			break
		}
	}
	i.RUnlock()
}

type MultiIndex struct {
	lookup map[AttributeValuePair]*ObjectSlice
	sync.RWMutex
}

func (i *MultiIndex) init() {
	i.lookup = make(map[AttributeValuePair]*ObjectSlice)
}

func (i *MultiIndex) Lookup(key, key2 AttributeValue) (ObjectSlice, bool) {
	iv := AttributeValueToIndex(key)
	iv2 := AttributeValueToIndex(key2)

	i.RLock()
	result, found := i.lookup[AttributeValuePair{iv, iv2}]
	i.RUnlock()
	if !found {
		return ObjectSlice{}, false
	}
	return *result, found
}

func (i *MultiIndex) Add(key, key2 AttributeValue, o *Object, undupe bool) {
	iv := AttributeValueToIndex(key)
	iv2 := AttributeValueToIndex(key2)
	avp := AttributeValuePair{iv, iv2}
	i.Lock()
	existing, found := i.lookup[avp]
	if !found {
		new := NewObjectSlice(0)
		i.lookup[avp] = &new
		existing = &new
	}
	if undupe && existing.Len() > 0 {
		dupefound := false
		existing.Iterate(func(eo *Object) bool {
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

func (i *MultiIndex) Iterate(each func(key, key2 AttributeValue, objects ObjectSlice) bool) {
	i.RLock()
	for pair, value := range i.lookup {
		if !each(pair.Value1, pair.Value2, *value) {
			break
		}
	}
	i.RUnlock()
}
