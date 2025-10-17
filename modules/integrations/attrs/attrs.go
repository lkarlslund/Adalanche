package attrs

import "github.com/lkarlslund/adalanche/modules/engine"

var (
	DomainJoinedSID = engine.NewAttribute("domainJoinedSID").Flag(engine.Single, engine.Merge)
)
