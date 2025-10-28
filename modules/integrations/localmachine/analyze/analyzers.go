package analyze

import (
	"net"
	"sync"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func LinkSCCM(ao *engine.IndexedGraph) {
	ao.Iterate(func(o *engine.Node) bool {
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
					DNSHostname, engine.NV(host),
					engine.Type, engine.NV("Machine"),
				)
				// .. or fallback to just the name
				if !found {
					servers, found = ao.FindTwoMulti(
						engine.Name, engine.NV(host),
						engine.Type, engine.NV("Machine"),
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
				servers.Iterate(func(server *engine.Node) bool {
					ao.EdgeTo(server, o, EdgeControlsUpdates)
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
	loader.AddProcessor(

		func(ao *engine.IndexedGraph) {
			var mut sync.Mutex
			sids := make(map[windowssecurity.SID][]*engine.Node)
			ao.IterateParallel(func(o *engine.Node) bool {
				if o.Type() != engine.NodeTypeMachine {
					return true
				}
				sid := o.SID()
				if sid.IsBlank() {
					return true
				}
				mut.Lock()
				sids[sid] = append(sids[sid], o)
				mut.Unlock()
				return true
			}, 0)

			for _, nodes := range sids {
				if len(nodes) < 2 {
					continue
				}
				for i := range nodes {
					for j := i + 1; j < len(nodes); j++ {
						if i == j {
							continue
						}
						ao.EdgeTo(nodes[i], nodes[j], EdgeSIDCollision)
					}
				}
			}

		},
		"Local SID collisions",
		engine.AfterMerge,
	)
}
