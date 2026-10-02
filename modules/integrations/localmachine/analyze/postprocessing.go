package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func init() {
	loader.AddProcessor(linkLocalAccountsToMachines, engine.Processor{
		Description: "Link local users and groups to machines",
		Phase:       engine.BeforeMerge,
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
			Phase:       engine.AfterMerge,
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
