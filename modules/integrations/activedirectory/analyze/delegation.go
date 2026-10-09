package analyze

import (
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/util"
)

var edgeConstrainedDelegation = engine.NewEdge("ConstrainedDeleg").Describe("Delegation to a configured service. Without protocol transition, requires a suitable forwardable service ticket.")

func addConstrainedDelegationEdges(tx *engine.Tx) {
	var missingTargets int
	tx.Iterate(func(o *engine.Node) bool {
		// Only computers and users
		if o.Type() != engine.NodeTypeComputer && o.Type() != engine.NodeTypeUser {
			return true
		}
		var missing engine.AttributeValues
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
			if target, found := tx.FindTwo(DnsHostName, engine.NV(host),
				engine.Type, engine.NV("Machine"),
			); found {
				tx.EdgeBecause(o, target, edgeConstrainedDelegation, AttributeCause(o, activedirectory.MSDSAllowedToDelegateTo))
			} else if !delegationTargetExists(tx, val, host) {
				missing = append(missing, val)
			}

			return true
		})
		if len(missing) > 0 {
			missingTargets += len(missing)
			tx.Node(o).Set(MissingDelegationTargets, missing...).Tag(TagDelegationTargetMissing)
		}
		return true
	})
	if missingTargets > 0 {
		ui.Info().Msgf("%v constrained delegation services name hosts or accounts that are not found, tagged %v", missingTargets, TagDelegationTargetMissing)
	}
}

// delegationTargetExists reports whether a delegation service names something
// in the directory: a machine with the host name (also when several match),
// or an account that registered the service principal name, such as a service
// account behind a DNS alias.
func delegationTargetExists(tx *engine.Tx, spn engine.AttributeValue, host string) bool {
	if _, found := tx.FindTwoMulti(DnsHostName, engine.NV(host), engine.Type, engine.NV("Machine")); found {
		return true
	}
	_, found := tx.FindMulti(activedirectory.ServicePrincipalName, spn)
	return found
}
