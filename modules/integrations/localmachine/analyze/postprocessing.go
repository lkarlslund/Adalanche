package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	adanalyze "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	"github.com/lkarlslund/adalanche/modules/integrations/attrs"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func init() {
	loader.AddProcessor(linkDomainGroupsToMachines, engine.Processor{
		Description: "Domain's Everyone and Authenticated Users are members of a joined machine's",
		Phase:       engine.AnalysisPhase,
		Needs:       []engine.Product{adanalyze.ProductMachines, adanalyze.ProductWellKnownPrincipals},
		Provides:    []engine.Product{ProductDomainGroups},
	})

	loader.AddProcessor(linkLocalAccountsToMachines, engine.Processor{
		Description: "Link local users and groups to machines",
		Phase:       engine.LoaderPhase,
		Provides:    []engine.Product{ProductLocalTree},
	})

	loader.AddProcessor(func(tx *engine.Tx) {
		var warns int
		ln := engine.NV(Loadername)
		tx.Iterate(func(o *engine.Node) bool {
			if o.HasAttrValue(engine.DataLoader, ln) {
				if o.HasAttr(activedirectory.ObjectSid) {
					edgesOut := 0
					tx.IterateEdges(o, engine.Out, func(*engine.Node, engine.EdgeBitmap) bool {
						edgesOut++
						return false
					})
					edgesIn := 0
					tx.IterateEdges(o, engine.In, func(*engine.Node, engine.EdgeBitmap) bool {
						edgesIn++
						return false
					})
					if edgesOut+edgesIn == 0 {
						ui.Debug().Msgf("Object has no graph connections: %v", o.Label())
					}
					warns++
					if warns > 100 {
						ui.Debug().Msg("Stopping warnings about graph connections, too much output")
						return false
					}
				}
			}
			return true
		})
	},
		engine.Processor{
			Description: "Detecting broken links",
			Phase:       engine.AnalysisPhase,
			Final:       true,
		})
}

// linkLocalAccountsToMachines puts local users and groups under the machine
// whose local SID they share, from the same collection.
func linkLocalAccountsToMachines(tx *engine.Tx) {
	// Computer accounts are not linked: they are either absorbed into the
	// real computer object, or orphaned.
	type machineKey struct {
		source engine.AttributeValue
		sid    windowssecurity.SID
	}
	machines := map[machineKey]*engine.Node{}
	ambiguous := map[machineKey]bool{}
	candidates, _ := tx.FindMulti(engine.Type, engine.NV("Machine"))
	candidates.Iterate(func(m *engine.Node) bool {
		source := m.OneAttr(engine.DataSource)
		m.Attr(LocalMachineSID).Iterate(func(v engine.AttributeValue) bool {
			if sid, ok := v.Raw().(windowssecurity.SID); ok {
				key := machineKey{source, sid}
				if seen, found := machines[key]; found && seen != m {
					ambiguous[key] = true
				}
				machines[key] = m
			}
			return true
		})
		return true
	})
	for _, nodeType := range []engine.NodeType{engine.NodeTypeUser, engine.NodeTypeGroup} {
		accounts, _ := tx.FindMulti(engine.Type, nodeType.ValueString())
		accounts.Iterate(func(o *engine.Node) bool {
			if !o.HasAttr(activedirectory.ObjectSid) || !o.HasAttr(engine.DataSource) {
				return true
			}
			key := machineKey{o.OneAttr(engine.DataSource), o.SID().StripRID()}
			if machine, found := machines[key]; found && !ambiguous[key] {
				tx.Node(o).ChildOf(machine)
			}
			return true
		})
	}
}

// linkDomainGroupsToMachines makes a domain's Everyone and Authenticated
// Users members of the same groups on each machine joined to the domain:
// whoever the domain authenticates is one of them when using the machine.
func linkDomainGroupsToMachines(tx *engine.Tx) {
	machines, _ := tx.FindMulti(engine.Type, engine.NV("Machine"))
	machines.Iterate(func(machine *engine.Node) bool {
		joined := machine.OneAttr(attrs.DomainJoinedSID)
		if joined.IsNil() {
			return true
		}
		// The machine's computer account carries its domain.
		var computer *engine.Node
		candidates, _ := tx.FindMulti(engine.ObjectSid, joined)
		candidates.Iterate(func(c *engine.Node) bool {
			if c.Type() == engine.NodeTypeComputer && c.HasAttr(engine.DomainContext) {
				computer = c
				return false
			}
			return true
		})
		if computer == nil {
			return true
		}
		for _, sid := range []windowssecurity.SID{windowssecurity.EveryoneSID, windowssecurity.AuthenticatedUsersSID} {
			// The machine's own group is the one placed under it.
			var local *engine.Node
			machine.Children().Iterate(func(child *engine.Node) bool {
				if child.SID() == sid {
					local = child
					return false
				}
				return true
			})
			domain, found := tx.FindAdjacentSID(sid, computer)
			if local == nil || !found || domain == local {
				continue
			}
			tx.EdgeBecauseEx(domain, local, activedirectory.EdgeMemberOfGroup, true, adanalyze.Inferred("the domain's principals are members on machines joined to it"))
		}
		return true
	})
}
