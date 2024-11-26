package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func init() {
	loader.AddProcessor(func(ao *engine.Objects) {
		ao.Iterate(func(o *engine.Object) bool {
			if o.HasAttr(activedirectory.ObjectSid) && o.HasAttr(engine.DataSource) {

				// We can do this with confidence as everything comes from this loader
				sidwithoutrid := o.OneAttrRaw(activedirectory.ObjectSid).(windowssecurity.SID).StripRID()

				switch o.Type() {
				case engine.ObjectTypeComputer:
					// We don't link that - it's either absorbed into the real computer object, or it's orphaned
				case engine.ObjectTypeUser:
					// It's a User we added, find the machine
					if machine, found := ao.FindTwo(
						engine.DataSource, o.OneAttr(engine.DataSource),
						LocalMachineSID, engine.NewAttributeValueSID(sidwithoutrid)); found {
						o.ChildOf(machine) // FIXME -> Users
					}
				case engine.ObjectTypeGroup:
					// It's a Group we added
					if machine, found := ao.FindTwo(
						engine.DataSource, o.OneAttr(engine.DataSource),
						LocalMachineSID, engine.NewAttributeValueSID(sidwithoutrid)); found {
						o.ChildOf(machine) // FIXME -> Groups
					}
				default:
					// if o.HasAttr(activedirectory.ObjectSid) {
					// 	if computer, found := ld.ao.FindTwo(
					// 		engine.UniqueSource, o.OneAttr(engine.UniqueSource),
					// 		LocalMachineSID, engine.NewAttributeValueSID(sidwithoutrid)); found {
					// 		o.ChildOf(computer) // We don't know what it is
					// 	}
					// }
				}
			}
			return true
		})
	}, "Link local users and groups to machines", engine.BeforeMergeLow)

	loader.AddProcessor(func(ao *engine.Objects) {
		var warns int
		ln := engine.NewAttributeValueString(Loadername)
		ao.Iterate(func(o *engine.Object) bool {
			if o.HasAttrValue(engine.DataLoader, ln) {
				if o.HasAttr(activedirectory.ObjectSid) {
					if o.Edges(engine.Out).Len()+o.Edges(engine.In).Len() == 0 {
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
		"Detecting broken links",
		engine.AfterMergeHigh,
	)
}
