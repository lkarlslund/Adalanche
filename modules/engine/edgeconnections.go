package engine

import (
	gsync "github.com/SaveTheRbtz/generic-sync-map-go"
	"github.com/rs/zerolog/log"
)

type EdgeConnections struct {
	ecm gsync.MapOf[*Object, *EdgeBitmap]
	// ecm *haxmap.Map[ObjectID, *EdgeBitmap]
	// ecm *hashmap.Map[ObjectID, *EdgeBitmap]
}

func (ec *EdgeConnections) init() {
	ec.ecm = gsync.MapOf[*Object, *EdgeBitmap]{}
	// ec.ecm = hashmap.New[ObjectID, *EdgeBitmap]()
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
	// if ec.ecm == nil {
	// 	return
	// }
	ec.ecm.Range(func(target *Object, eb *EdgeBitmap) bool {
		if target == nil {
			log.Warn().Msg("Unpossible 2: Top Secret Mission")
			return true
		}
		return rf(target, *eb)
	})
}

func (ec *EdgeConnections) RangeID(rf func(ObjectID, EdgeBitmap) bool) {
	// if ec.ecm == nil {
	// 	return
	// }
	ec.ecm.Range(func(target *Object, eb *EdgeBitmap) bool {
		return rf(target.id, *eb)
	})
}

func (ec *EdgeConnections) Len() int {
	var count int
	ec.RangeID(func(id ObjectID, eb EdgeBitmap) bool {
		count++
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

func (ec *EdgeConnections) GetOrSet(o *Object, eb *EdgeBitmap) (*EdgeBitmap, bool) {
	// res, status := ec.ecm.GetOrInsert(o.ID(), eb)
	// res, status := ec.ecm.GetOrSet(o.ID(), eb)
	res, status := ec.ecm.LoadOrStore(o, eb)
	return res, status
}

func (ec *EdgeConnections) Set(o *Object, edge *EdgeBitmap) {
	// ec.ecm.Set(o.ID(), edge)
	ec.ecm.Store(o, edge)
}

var GlobalFSPartOfGPO uint32

// Thread safe stuff from here
func (ec *EdgeConnections) SetEdge(o *Object, edge Edge) (*EdgeBitmap, bool) {
	// edges, loaded := ec.ecm.Get(o.ID())
	edges, loaded := ec.ecm.Load(o)
	if !loaded {
		// This is to avoid allocating EdgeBitmap way too many times
		// edges, loaded = ec.ecm.GetOrSet(o.ID(), &EdgeBitmap{})
		// edges, loaded = ec.ecm.GetOrInsert(o.ID(), &EdgeBitmap{})
		edges, loaded = ec.ecm.LoadOrStore(o, &EdgeBitmap{})
	}
	edges.AtomicSet(edge)
	return edges, loaded
}

func (ec *EdgeConnections) ClearEdge(o *Object, edge Edge) {
	// p, found := ec.ecm.Get(o.ID())
	p, found := ec.ecm.Load(o)
	if found {
		p.AtomicClear(edge)
	}
}

func (ec *EdgeConnections) SetEdges(o *Object, edges EdgeBitmap) {
	// p, loaded := ec.ecm.Get(o.ID())
	p, loaded := ec.ecm.Load(o)
	if !loaded {
		// This is to avoid allocating EdgeBitmap way too many times
		// p, _ = ec.ecm.GetOrInsert(o.ID(), &EdgeBitmap{})
		// p, _ = ec.ecm.GetOrSet(o.ID(), &EdgeBitmap{})
		p, _ = ec.ecm.LoadOrStore(o, &EdgeBitmap{})
	}
	p.AtomicOr(edges)
}

func (ec *EdgeConnections) ClearEdges(o *Object, edges EdgeBitmap) {
	// p, found := ec.ecm.Get(o.ID())
	p, found := ec.ecm.Load(o)
	if found {
		p.AtomicAnd(edges.Invert())
	}
}

func (ec *EdgeConnections) Del(o *Object) {
	// ec.ecm.Del(o)
	ec.ecm.Delete(o)
}
