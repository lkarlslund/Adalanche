package engine

import "github.com/gofrs/uuid"

type ObjectSlice []*Object

func (os ObjectSlice) Len() int {
	return len(os)
}

func (os ObjectSlice) Less(i, j int) bool {
	for n := 0; n < uuid.Size; n++ {
		if os[i].GUID()[n] < os[j].GUID()[n] {
			return true
		}
		if os[i].GUID()[n] > os[j].GUID()[n] {
			break
		}
	}
	return false
}

func (os ObjectSlice) Swap(i, j int) {
	os[i], os[j] = os[j], os[i]
}
