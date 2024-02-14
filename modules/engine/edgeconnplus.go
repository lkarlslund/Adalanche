package engine

import (
	"unsafe"

	"github.com/lkarlslund/gonk"
)

type EdgeConnectionsPlus struct {
	gonk.Gonk[Connection]
}

type Connection struct {
	target *Object
	edges  EdgeBitmap
}

func (c Connection) LessThan(c2 Connection) bool {
	return uintptr(unsafe.Pointer(c.target)) < uintptr(unsafe.Pointer(c2.target))
}

func (ecp *EdgeConnectionsPlus) Range(rf func(o *Object, eb EdgeBitmap) bool) {
	ecp.Gonk.Range(func(c Connection) bool {
		return rf(c.target, c.edges)
	})
}

func (ecp *EdgeConnectionsPlus) del(o *Object) {
	ecp.Gonk.Delete(Connection{
		target: o,
	})
}

func (e *EdgeConnectionsPlus) setEdges(target *Object, edge EdgeBitmap) {
	e.Gonk.AtomicMutate(Connection{
		target: target,
	}, func(c *Connection) {
		c.edges.AtomicOr(edge)
	}, true)
}

func (e *EdgeConnectionsPlus) clearEdge(target *Object, edge Edge) {
	e.Gonk.AtomicMutate(Connection{
		target: target,
	}, func(c *Connection) {
		c.edges.AtomicClear(edge)
	}, true)
}

func (e *EdgeConnectionsPlus) setEdge(target *Object, edge Edge) {
	e.setEdges(target, EdgeBitmap{}.Set(edge))
}
