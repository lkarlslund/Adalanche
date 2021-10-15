package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/rs/zerolog/log"
)

func init() {
	engine.AddPostprocessor(func(ao *engine.Objects) {
		for _, o := range ao.AsArray() {
			if o.HasAttrValue(engine.MetaDataSource, engine.AttributeValueString(myloader.Name())) {
				if o.HasAttr(engine.ObjectSid) {
					if len(o.CanPwn) == 0 {
						log.Warn().Msgf("Object from JSON files can't reach anything: %v", o.Label())
					}
					// if o.Attr(engine.MetaDataSource).Len() < 2 {
					// 	log.Warn().Msgf("Unjoined object %v", o.Label())
					// }
				}
			}
		}
	}, "Detecting broken links")
}
