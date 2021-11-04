package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/rs/zerolog/log"
)

func init() {
	engine.PostProcessing.AddProcessor(func(ao *engine.Objects) {
		var warns int
		for _, o := range ao.Slice() {
			if o.HasAttrValue(engine.MetaDataSource, engine.AttributeValueString(myloader.Name())) {
				if o.HasAttr(activedirectory.ObjectSid) {
					if len(o.CanPwn) == 0 && len(o.PwnableBy) == 0 {
						log.Debug().Msgf("Object has no graph connections: %v", o.Label())
					}
					warns++
					if warns > 500 {
						log.Debug().Msg("Stopping warnings about graph connections, too much output")
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
