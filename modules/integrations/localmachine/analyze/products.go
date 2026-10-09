package analyze

import "github.com/lkarlslund/adalanche/modules/engine"

// Products made by the local machine processors.
const (
	// Local users and groups placed under their machine.
	ProductLocalTree engine.Product = "localmachine/tree"
	// Edges from SCCM and WSUS servers to the computers they manage.
	ProductUpdateControl engine.Product = "localmachine/update-control"
	// The domain's Everyone and Authenticated Users linked to each machine's.
	ProductDomainGroups engine.Product = "localmachine/domain-groups"
	// SIDCollision edges between machines sharing a machine SID.
	ProductSIDCollisions engine.Product = "localmachine/sid-collisions"
)
