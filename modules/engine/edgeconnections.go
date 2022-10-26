package engine

import (
	"sort"
	"sync"

	gsync "github.com/SaveTheRbtz/generic-sync-map-go"
)

type EdgeConnections struct {
	ecm  gsync.MapOf[uint32, EdgeBitmap]
	lock sync.Mutex // For stable modification of edges
	// m *haxmap.Map[unsafe.Pointer, EdgeBitmap]
}

var globalEdgeConnectionsLock sync.Mutex // Ugly but it will do

func (ec *EdgeConnections) StringMap() map[string]string {
	result := make(map[string]string)
	ec.RangeID(func(id uint32, eb EdgeBitmap) bool {
		result[IDtoObject(id).Label()] = eb.JoinedString()
		return true
	})
	return result
}

// Thread safe range
func (ec *EdgeConnections) Range(rf func(*Object, EdgeBitmap) bool) {
	ec.ecm.Range(func(id uint32, eb EdgeBitmap) bool {
		return rf(IDtoObject(id), eb)
	})
}

func (ec *EdgeConnections) RangeID(rf func(uint32, EdgeBitmap) bool) {
	ec.ecm.Range(func(id uint32, eb EdgeBitmap) bool {
		return rf(id, eb)
	})
}

func (ec *EdgeConnections) Len() int {
	var count int
	ec.RangeID(func(id uint32, eb EdgeBitmap) bool {
		count++
		return true
	})
	return count
}

func (ec *EdgeConnections) Objects() ObjectSlice {
	result := make(ObjectSlice, ec.Len())
	var i int
	ec.Range(func(o *Object, eb EdgeBitmap) bool {
		result[i] = o
		i++
		return true
	})
	sort.Sort(result)
	return result
}

// func (ec *EdgeConnections) Get(o *Object) (EdgeBitmap, bool) {
// 	return ec.m.Load(o.ID())
// }

func (ec *EdgeConnections) GetOrSet(o *Object, eb EdgeBitmap) (EdgeBitmap, bool) {
	ec.lock.Lock()
	res, status := ec.ecm.LoadOrStore(o.ID(), eb)
	ec.lock.Unlock()
	return res, status
}

func (ec *EdgeConnections) Set(o *Object, edge EdgeBitmap) {
	ec.lock.Lock()
	ec.ecm.Store(o.ID(), edge)
	ec.lock.Unlock()
}

var GlobalFSPartOfGPO uint32

func (ec *EdgeConnections) SetEdge(o *Object, edge Edge) {
	ec.lock.Lock()
	p, _ := ec.ecm.Load(o.ID())
	newedge := p.Set(edge)
	ec.ecm.Store(o.ID(), newedge)
	ec.lock.Unlock()
}

func (ec *EdgeConnections) ClearEdge(o *Object, edge Edge) {
	ec.lock.Lock()
	p, loaded := ec.ecm.Load(o.ID())
	if !loaded {
		ec.lock.Unlock()
		return
	}
	newedge := p.Clear(edge)
	ec.ecm.Store(o.ID(), newedge)
	ec.lock.Unlock()
}

func (ec *EdgeConnections) Del(o *Object) {
	ec.lock.Lock()
	ec.ecm.Delete(o.ID())
	ec.lock.Unlock()
}
