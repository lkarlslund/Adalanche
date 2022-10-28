package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/ui"
)

func LinkSCCM(ao *engine.Objects) {
	ao.Iterate(func(o *engine.Object) bool {
		if o.HasAttr(WUServer) || o.HasAttr(SCCMServer) {
			var hosts []string
			if hostname := o.OneAttrString(WUServer); hostname != "" {
				hosts = append(hosts, hostname)
			}

			if hostname := o.OneAttrString(SCCMServer); hostname != "" {
				hosts = append(hosts, hostname)
			}

			for _, host := range hosts {
				servers, found := ao.FindTwoMulti(
					DNSHostname, engine.AttributeValueString(host),
					engine.ObjectCategorySimple, engine.AttributeValueString("Machine"),
				)
				if !found {
					ui.Warn().Msgf("Could not find controlling WSUS or SCCM server %v for %v", host, o.Label())
					continue
				}
				servers.Iterate(func(server *engine.Object) bool {
					server.EdgeTo(o, EdgeControlsUpdates)
					return true
				})
			}
		}
		return true
	})
}

func init() {
	loader.AddProcessor(
		LinkSCCM,
		"Link SCCM and WSUS servers to controlled computers",
		engine.AfterMerge,
	)
}
