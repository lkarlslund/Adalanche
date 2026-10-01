package analyze

import "github.com/lkarlslund/adalanche/modules/engine"

// Products made by the local machine processors.
const (
	// Local users and groups placed under their machine.
	ProductLocalTree engine.Product = "localmachine/tree"
	// Edges from SCCM and WSUS servers to the computers they manage.
	ProductUpdateControl engine.Product = "localmachine/update-control"
	// SIDCollision edges between machines sharing a machine SID.
	ProductSIDCollisions engine.Product = "localmachine/sid-collisions"
)
