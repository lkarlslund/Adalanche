package engine

import (
	"github.com/lkarlslund/gonk"
)

type EdgeConnectionsPlus struct {
	gonk.Gonk[Connection]
}

type Connection struct {
	target *Object
	edges  EdgeBitmap
}

func (c Connection) Compare(c2 Connection) int {
	return int(c.target.id) - int(c2.target.id) // using internal id, object might be invalidated
}

func (c Connection) LessThan(c2 Connection) bool {
	return c.target.id < c2.target.id // using internal id, object might be invalidated
}

func (ecp *EdgeConnectionsPlus) Range(rf func(o *Object, eb EdgeBitmap) bool) {
	ecp.Gonk.Range(func(c *Connection) bool {
		return rf(c.target, c.edges.PartialAtomicLoad())
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
	e.Gonk.AtomicMutate(Connection{
		target: target,
	}, func(c *Connection) {
		c.edges.AtomicSet(edge)
	}, true)
}
