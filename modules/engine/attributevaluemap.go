package engine

import (
	gsync "github.com/SaveTheRbtz/generic-sync-map-go"
)

type AttributeValueMap struct {
	// m *xsync.MapOf[Attribute, AttributeValues]
	// m map[Attribute]AttributeValues
	// m *haxmap.Map[Attribute, AttributeValues]
	m gsync.MapOf[Attribute, AttributeValues]
}

func (avm *AttributeValueMap) init(preloadAttributes int) {
	// avm.m = haxmap.New[Attribute, AttributeValues](1)
	// avm.m = make(map[Attribute]AttributeValues)
	// avm.m = xsync.NewTypedMapOf[Attribute, AttributeValues](func(a Attribute) uint64 {
	// 	return uint64(a)
	// })
}

func (avm *AttributeValueMap) Get(a Attribute) (av AttributeValues, found bool) {
	// av, found = avm.m.Get(a)
	// if found && av.Len() == 0 {
	// 	found = false // workaround until haxmap performance for deletes is fixed
	// }
	// av, found = avm.m[a]
	av, found = avm.m.Load(a)
	return
}

func (avm *AttributeValueMap) Set(a Attribute, av AttributeValues) {
	// avm.m.Set(a, av)
	// avm.m[a] = av
	avm.m.Store(a, av)
}

func (avm *AttributeValueMap) Len() int {
	var count int
	avm.m.Range(func(u Attribute, av AttributeValues) bool {
		// if av.Len() > 0 {
		count++
		// }
		return true
	})
	return count
	// return len(avm.m)
	// return avm.m.Size()
}

func (avm *AttributeValueMap) Clear(a Attribute) {
	// avm.m.Set(a, NoValues{}) // Workaround until haxmap performance
	// delete(avm.m, a)
	avm.m.Delete(a)
}

func (avm *AttributeValueMap) Iterate(f func(attr Attribute, values AttributeValues) bool) {
	avm.m.Range(f)
	// for a, av := range avm.m {
	// 	if !f(a, av) {
	// 		break
	// 	}
	// }
	// avm.m.Range(func(a Attribute, av AttributeValues) bool {
	// 	return f(a, av)
	// })
}
