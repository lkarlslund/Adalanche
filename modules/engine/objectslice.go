package engine

import (
	"bytes"
	"sort"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

type ObjectSlice struct {
	objects []*Object
}

func NewObjectSlice(prealloc int) ObjectSlice {
	return ObjectSlice{
		objects: make([]*Object, 0, prealloc),
	}
}

func (os ObjectSlice) Len() int {
	return len(os.objects)
}

func (os *ObjectSlice) Add(o *Object) {
	os.objects = append(os.objects, o)
	// os.objects = append(os.objects, o.ID())
}

// func (os *ObjectSlice) AddID(id ObjectID) {
// 	os.objects = append(os.objects, id)
// }

// func (os *ObjectSlice) RemoveID(id ObjectID) {
// 	for i, curid := range os.objects {
// 		if curid.id == id {
// 			if len(os.objects) == 1 {
// 				os.objects = nil
// 			} else {
// 				os.objects[i] = os.objects[len(os.objects)-1]
// 				os.objects = os.objects[:len(os.objects)-1]
// 			}
// 			return
// 		}
// 	}
// 	panic("Asked to remove item from ObjectSlice that isn't there")
// }

func (os *ObjectSlice) Remove(o *Object) {
	for i, cur := range os.objects {
		if cur == o {
			if len(os.objects) == 1 {
				os.objects = nil
			} else {
				os.objects[i] = os.objects[len(os.objects)-1]
				os.objects = os.objects[:len(os.objects)-1]
			}
			return
		}
	}
	panic("Asked to remove item from ObjectSlice that isn't there")
}

// func (os ObjectSlice) Less(i, j int) bool {
// 	for n := 0; n < uuid.Size; n++ {
// 		if os.objects[i].Object().GUID()[n] < os.objects[j].Object().GUID()[n] {
// 			return true
// 		}
// 		if os.objects[i].Object().GUID()[n] > os.objects[j].Object().GUID()[n] {
// 			break
// 		}
// 	}
// 	return false
// }

// func (os ObjectSlice) Swap(i, j int) {
// 	os.objects[i], os.objects[j] = os.objects[j], os.objects[i]
// }

func (os ObjectSlice) First() *Object {
	if len(os.objects) == 0 {
		return nil
	}
	return os.objects[0]
}

func (os ObjectSlice) Iterate(af func(o *Object) bool) {
	if os.objects == nil {
		return
	}
	for _, o := range os.objects {
		if !af(o) {
			break
		}
	}
}

// func (os ObjectSlice) IterateID(af func(id ObjectID) bool) {
// 	if os.objects == nil {
// 		return
// 	}
// 	for _, o := range os.objects {
// 		if !af(o.id) {
// 			break
// 		}
// 	}
// }

func (os *ObjectSlice) Sort(attr Attribute, reverse bool) {
	orderf := func(i, j int) bool {
		iv, ifound := os.objects[i].Get(attr)
		jv, jfound := os.objects[j].Get(attr)

		// No one has attribute, so not less
		if !ifound && !jfound {
			return false
		}
		// Only i does not have, so it is less
		if !ifound {
			return true
		}
		// Only j does not have, so it is not less
		if !jfound {
			return false
		}

		// Both have, so compare
		ir := iv.First().Raw()
		jr := jv.First().Raw()

		switch it := ir.(type) {
		case int64:
			jt, ok := jr.(int64)
			if !ok {
				return false // Not comparable
			}
			return it < jt
		case time.Time:
			jt, ok := jr.(time.Time)
			if !ok {
				return false // Not comparable
			}
			return it.Before(jt)
		case string:
			jt, ok := jr.(string)
			if !ok {
				return false // Not comparable
			}
			return strings.Compare(it, jt) == -1
		case []byte:
			jt, ok := jr.([]byte)
			if !ok {
				return false // Not comparable
			}
			return bytes.Compare(it, jt) == -1
		case bool:
			jt, ok := jr.(bool)
			if !ok {
				return false // Not comparable
			}
			return !it && jt
		case uuid.UUID:
			jt, ok := jr.(uuid.UUID)
			if !ok {
				return false // Not comparable
			}
			return bytes.Compare(it[:], jt[:]) == -1
		case windowssecurity.SID:
			jt, ok := jr.(windowssecurity.SID)
			if !ok {
				return false // Not comparable
			}
			components := it.Components()
			if jt.Components() < components {
				components = jt.Components()
			}
			for i := 0; i < components; i++ {
				if it.Component(i) == jt.Component(i) {
					continue
				}
				return it.Component(i) < jt.Component(i)
			}
			return it.Components() < jt.Components()
		}

		return false
	}

	if reverse {
		orderf = func(i, j int) bool {
			return !orderf(i, j)
		}
	}

	sort.Slice(os.objects, orderf)
}

func (os *ObjectSlice) SortFunc(lessthan func(o, o2 *Object) bool) {
	sort.Slice(os.objects, func(i int, j int) bool {
		return lessthan(os.objects[i], os.objects[j])
	})
}

func (os *ObjectSlice) Skip(count int) {
	if count > 0 {
		// from start
		if count > len(os.objects) {
			os.objects = os.objects[count:]
		} else {
			os.objects = os.objects[:0]
		}
	} else if count < 0 {
		// from end
		count = -count
		if count > len(os.objects) {
			os.objects = os.objects[:len(os.objects)-count]
		} else {
			os.objects = os.objects[:0]
		}
	}
}

func (os *ObjectSlice) Limit(count int) {
	if count > 0 {
		if count < len(os.objects) {
			os.objects = os.objects[:count]
		}
	} else if count < 0 {
		count = -count
		if count < len(os.objects) {
			os.objects = os.objects[len(os.objects)-count:]
		}
	}
}
