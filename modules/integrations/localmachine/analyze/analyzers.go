package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/ui"
)

func init() {
	loader.AddProcessor(
		func(ao *engine.Objects) {
			for _, o := range ao.Slice() {
				if o.HasAttr(WUServer) || o.HasAttr(SCCMServer) {
					var hosts []string
					if hostname := o.OneAttrString(WUServer); hostname != "" {
						hosts = append(hosts, hostname)
					}

					if hostname := o.OneAttrString(SCCMServer); hostname != "" {
						hosts = append(hosts, hostname)
					}

					for _, host := range hosts {
						servers, found := ao.FindTwoMultiOrAdd(
							DNSHostname, engine.AttributeValueString(host),
							engine.ObjectClass, engine.AttributeValueString("computer"),
							nil,
						)
						if !found {
							ui.Warn().Msgf("Could not find controlling WSUS or SCCM server %v for %v", host, o.DN())
							continue
						}
						for _, server := range servers {
							server.Pwns(o, PwnControlsUpdates)
						}
					}
				}
			}
		},
		"Link SCCM and WSUS servers to controlled computers",
		engine.AfterMerge,
	)

}
