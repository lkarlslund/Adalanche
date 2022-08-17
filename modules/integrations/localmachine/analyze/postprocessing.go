package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
)

func init() {
	loader.AddProcessor(func(ao *engine.Objects) {
		var warns int
		ln := engine.AttributeValueString(loadername)
		for _, o := range ao.Slice() {
			if o.HasAttrValue(engine.MetaDataSource, ln) {
				if o.HasAttr(activedirectory.ObjectSid) {
					if len(o.CanPwn) == 0 && len(o.PwnableBy) == 0 {
						ui.Debug().Msgf("Object has no graph connections: %v", o.Label())
					}
					warns++
					if warns > 100 {
						ui.Debug().Msg("Stopping warnings about graph connections, too much output")
						break
					}
				}
			}
		}
	},
		"Detecting broken links",
		engine.AfterMergeHigh,
	)
}
