package analyze

import (
	"net"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/ui"
)

func LinkSCCM(ao *engine.Objects) {
	ao.Iterate(func(o *engine.Object) bool {
		if o.HasAttr(WUServer) || o.HasAttr(SCCMServer) {
			var hosts []string
			controltype := "unknown"
			if hostname := o.OneAttrString(WUServer); hostname != "" {
				controltype = "WSUS"
				hosts = append(hosts, hostname)
			} else if hostname := o.OneAttrString(SCCMServer); hostname != "" {
				controltype = "SCCM"
				hosts = append(hosts, hostname)
			}

			for _, host := range hosts {
				// Try full DNS name
				servers, found := ao.FindTwoMulti(
					DNSHostname, engine.NewAttributeValueString(host),
					engine.Type, engine.NewAttributeValueString("Machine"),
				)
				// .. or fallback to just the name
				if !found {
					servers, found = ao.FindTwoMulti(
						engine.Name, engine.NewAttributeValueString(host),
						engine.Type, engine.NewAttributeValueString("Machine"),
					)
				}
				if !found {
					// try to parse host as IP
					ip := net.ParseIP(host)
					if ip != nil {
						ui.Warn().Msgf("Controlling %v server is referred to by IP address %v, unable to link it", controltype, host)
					}
					continue
				}
				if !found {
					ui.Warn().Msgf("Could not find controlling %v server %v for %v", controltype, host, o.Label())
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
