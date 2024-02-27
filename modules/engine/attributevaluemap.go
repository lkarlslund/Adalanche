package engine

import (
	"github.com/lkarlslund/gonk"
)

type AttributeValueMap struct {
	// m *xsync.MapOf[Attribute, AttributeValues]
	// m map[Attribute]AttributeValues
	// m *haxmap.Map[Attribute, AttributeValues]
	// m gsync.MapOf[Attribute, AttributeValues]
	m gonk.Gonk[AttributeValuesEvaluator]
}

type AttributeValuesEvaluator struct {
	a Attribute
	v AttributeValues
}

func (ave AttributeValuesEvaluator) Compare(ave2 AttributeValuesEvaluator) int {
	return int(ave.a) - int(ave2.a)
}

func (ave AttributeValuesEvaluator) Equal(ave2 AttributeValuesEvaluator) bool {
	return ave.a == ave2.a
}

func (ave AttributeValuesEvaluator) LessThan(ave2 AttributeValuesEvaluator) bool {
	return ave.a < ave2.a
}

func (avm *AttributeValueMap) init(preloadAttributes int) {
	avm.m.Init(preloadAttributes)
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
	// av, found = avm.m.Load(a)
	// return

	ave, found := avm.m.Load(AttributeValuesEvaluator{a: a})
	return ave.v, found
}

func (avm *AttributeValueMap) Set(a Attribute, av AttributeValues) {
	// avm.m.Set(a, av)
	// avm.m[a] = av
	// avm.m.Store(a, av)

	avm.m.Store(AttributeValuesEvaluator{a: a, v: av})
}

func (avm *AttributeValueMap) Len() int {
	// var count int
	// avm.m.Range(func(u Attribute, av AttributeValues) bool {
	// 	// if av.Len() > 0 {
	// 	count++
	// 	// }
	// 	return true
	// })
	// return count
	return avm.m.Len()
	// return len(avm.m)
	// return avm.m.Size()
}

func (avm *AttributeValueMap) Clear(a Attribute) {
	// avm.m.Set(a, NoValues{}) // Workaround until haxmap performance
	// delete(avm.m, a)
	// avm.m.Delete(a)
	// avm.m.Delete(AttributeValuesEvaluator{a: a})
	avm.m.Delete(AttributeValuesEvaluator{a: a})
}

func (avm *AttributeValueMap) Iterate(f func(attr Attribute, values AttributeValues) bool) {
	avm.m.Range(func(item AttributeValuesEvaluator) bool {
		return f(item.a, item.v)
	})
	// for a, av := range avm.m {
	// 	if !f(a, av) {
	// 		break
	// 	}
	// }
	// avm.m.Range(func(a Attribute, av AttributeValues) bool {
	// 	return f(a, av)
	// })
}
