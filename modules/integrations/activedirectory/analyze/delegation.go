package analyze

import (
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/util"
)

var edgeConstrainedDelegation = engine.NewEdge("ConstrainedDeleg").Describe("Delegation to a configured service. Without protocol transition, requires a suitable forwardable service ticket.")

func addConstrainedDelegationEdges(ao *engine.IndexedGraph) {
	ao.Iterate(func(o *engine.Node) bool {
		// Only computers and users
		if o.Type() != engine.NodeTypeComputer && o.Type() != engine.NodeTypeUser {
			return true
		}
		o.Attr(activedirectory.MSDSAllowedToDelegateTo).Iterate(func(val engine.AttributeValue) bool {
			ui.Debug().Msgf("Found msDS-AllowedToDelegate on %v as %v", o.DN(), val.String())
			_, host, split := strings.Cut(val.String(), "/")
			if !split {
				ui.Error().Msgf("Constrained delegation SPN %v does not contain /", val.String())
				return true // continue
			}
			if strings.Contains(host, "/") {
				ui.Error().Msgf("Constrained delegation host name %v still contains /", val.String())
				return true // continue
			}
			if strings.Contains(host, ":") {
				ui.Debug().Msgf("Constrained delegation host name %v contains :, removing port", val.String())
				host = strings.Split(host, ":")[0]
			}
			if !strings.Contains(host, ".") {
				ui.Debug().Msgf("Constrained delegation host name %v is not FQDN, adding domain context DNS", val.String())
				host += "." + util.DomainContextToDomainSuffix(o.OneAttrString(engine.DomainContext))
			}
			if target, found := ao.FindTwo(DnsHostName, engine.NV(host),
				engine.Type, engine.NV("Machine"),
			); found {
				ao.EdgeTo(o, target, edgeConstrainedDelegation)
			} else {
				ui.Error().Msgf("Could not find constrained delegation SPN %v target (looked for machine %v) in the AD", val.String(), host)
			}

			return true
		})
		return true
	})
}
