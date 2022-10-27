package engine

import (
	"sync"
)

type Index struct {
	lookup map[AttributeValue][]*Object
	sync.RWMutex
}

func (i *Index) init() {
	i.lookup = make(map[AttributeValue][]*Object)
}

func (i *Index) Lookup(key AttributeValue) ([]*Object, bool) {
	iv := AttributeValueToIndex(key)
	i.RLock()
	result, found := i.lookup[iv]
	i.RUnlock()
	return result, found
}

func (i *Index) Add(key AttributeValue, o *Object, undupe bool) {
	iv := AttributeValueToIndex(key)
	i.Lock()
	if undupe {
		existing, _ := i.lookup[iv]
		for _, dupe := range existing {
			if dupe == o {
				i.Unlock()
				return
			}
		}
	}

	existing, _ := i.lookup[iv]
	i.lookup[iv] = append(existing, o)
	i.Unlock()
}

func (i *Index) Iterate(each func(key AttributeValue, objects []*Object) bool) {
	i.RLock()
	for key, value := range i.lookup {
		if !each(key, value) {
			break
		}
	}
	i.RUnlock()
}

type MultiIndex struct {
	lookup map[AttributeValuePair][]*Object
	sync.RWMutex
}

func (i *MultiIndex) init() {
	i.lookup = make(map[AttributeValuePair][]*Object)
}

func (i *MultiIndex) Lookup(key, key2 AttributeValue) ([]*Object, bool) {
	iv := AttributeValueToIndex(key)
	iv2 := AttributeValueToIndex(key2)

	i.RLock()
	result, found := i.lookup[AttributeValuePair{iv, iv2}]
	i.RUnlock()
	return result, found
}

func (i *MultiIndex) Add(key, key2 AttributeValue, o *Object, undupe bool) {
	iv := AttributeValueToIndex(key)
	iv2 := AttributeValueToIndex(key2)
	avp := AttributeValuePair{iv, iv2}
	i.Lock()
	if undupe {
		existing, _ := i.lookup[avp]
		for _, dupe := range existing {
			if dupe == o {
				i.Unlock()
				return
			}
		}
	}

	existing, _ := i.lookup[avp]
	i.lookup[avp] = append(existing, o)
	i.Unlock()
}

func (i *MultiIndex) Iterate(each func(key, key2 AttributeValue, objects []*Object) bool) {
	i.RLock()
	for pair, value := range i.lookup {
		if !each(pair.Value1, pair.Value2, value) {
			break
		}
	}
	i.RUnlock()
}
