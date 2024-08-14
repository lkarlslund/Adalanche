package engine

import (
	gsync "github.com/SaveTheRbtz/generic-sync-map-go"
	"github.com/lkarlslund/adalanche/modules/ui"
)

type EdgeConnections struct {
	ecm gsync.MapOf[*Object, *EdgeBitmap]
}

func (ec *EdgeConnections) init() {
}

func (ec *EdgeConnections) StringMap() map[string]string {
	result := make(map[string]string)
	ec.Range(func(target *Object, eb EdgeBitmap) bool {
		result[target.Label()] = eb.JoinedString()
		return true
	})
	return result
}

// Thread safe range
func (ec *EdgeConnections) Range(rf func(*Object, EdgeBitmap) bool) {
	ec.ecm.Range(func(target *Object, eb *EdgeBitmap) bool {
		if target == nil {
			return true
		}
		return rf(target, *eb)
	})
}

func (ec *EdgeConnections) RangeID(rf func(ObjectID, EdgeBitmap) bool) {
	ec.ecm.Range(func(target *Object, eb *EdgeBitmap) bool {
		return rf(target.id, *eb)
	})
}

func (ec *EdgeConnections) Len() int {
	var count int
	ec.RangeID(func(id ObjectID, eb EdgeBitmap) bool {
		if !eb.IsBlank() {
			count++
		}
		return true
	})
	return count
}

func (ec *EdgeConnections) Objects() ObjectSlice {
	result := NewObjectSlice(ec.Len())
	var i int
	ec.Range(func(o *Object, eb EdgeBitmap) bool {
		result.Add(o)
		i++
		return true
	})
	result.Sort(ObjectGUID, false)
	return result
}

func (ec *EdgeConnections) setEdges(o *Object, edges EdgeBitmap) {
	oldedges, _ := ec.ecm.LoadOrStore(o, &EdgeBitmap{})
	oldedges.AtomicOr(edges)
}

func (ec *EdgeConnections) setEdge(o *Object, edge Edge) {
	oldedges, _ := ec.ecm.LoadOrStore(o, &EdgeBitmap{})
	oldedges.AtomicSet(edge)
}

func (ec *EdgeConnections) clearEdge(o *Object, edge Edge) {
	oldedges, _ := ec.ecm.Load(o)
	oldedges.AtomicClear(edge)
}

func (ec *EdgeConnections) del(o *Object) {
	_, found := ec.ecm.Load(o)
	if !found {
		ui.Warn().Msgf("Not found")
	}
	ec.ecm.Delete(o)
}
