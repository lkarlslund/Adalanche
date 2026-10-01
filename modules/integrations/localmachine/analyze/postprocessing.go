package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func init() {
	loader.AddProcessor(func(ao *engine.IndexedGraph) {
		ao.IterateStable(func(o *engine.Node) bool {
			if o.HasAttr(activedirectory.ObjectSid) && o.HasAttr(engine.DataSource) {

				// We can do this with confidence as everything comes from this loader
				sidwithoutrid := o.OneAttrRaw(activedirectory.ObjectSid).(windowssecurity.SID).StripRID()

				switch o.Type() {
				case engine.NodeTypeComputer:
					// We don't link that - it's either absorbed into the real computer object, or it's orphaned
				case engine.NodeTypeUser:
					// It's a User we added, find the machine
					if machine, found := ao.FindTwo(
						engine.DataSource, o.OneAttr(engine.DataSource),
						LocalMachineSID, engine.NV(sidwithoutrid)); found {
						o.ChildOf(machine) // FIXME -> Users
					}
				case engine.NodeTypeGroup:
					// It's a Group we added
					if machine, found := ao.FindTwo(
						engine.DataSource, o.OneAttr(engine.DataSource),
						LocalMachineSID, engine.NV(sidwithoutrid)); found {
						o.ChildOf(machine) // FIXME -> Groups
					}
				default:
					// if o.HasAttr(activedirectory.ObjectSid) {
					// 	if computer, found := ld.ao.FindTwo(
					// 		engine.UniqueSource, o.OneAttr(engine.UniqueSource),
					// 		LocalMachineSID, engine.NV(sidwithoutrid)); found {
					// 		o.ChildOf(computer) // We don't know what it is
					// 	}
					// }
				}
			}
			return true
		})
	}, engine.Processor{
		Description: "Link local users and groups to machines",
		Phase:       engine.BeforeMerge,
		Provides:    []engine.Product{ProductLocalTree},
	})

	loader.AddReadOnlyProcessor(func(view *engine.FrozenGraph) {
		var warns int
		ln := engine.NV(Loadername)
		view.Iterate(func(o *engine.Node) bool {
			if o.HasAttrValue(engine.DataLoader, ln) {
				if o.HasAttr(activedirectory.ObjectSid) {
					edgesOut := 0
					view.IterateEdges(o, engine.Out, func(*engine.Node, engine.EdgeBitmap) bool {
						edgesOut++
						return false
					})
					edgesIn := 0
					view.IterateEdges(o, engine.In, func(*engine.Node, engine.EdgeBitmap) bool {
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
