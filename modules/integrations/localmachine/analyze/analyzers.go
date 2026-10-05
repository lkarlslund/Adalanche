package analyze

import (
	"net"
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/engine"
	adanalyze "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func LinkSCCMProcessor(tx *engine.Tx) {
	// Only machines name update servers, and servers are machines: match
	// host names among them instead of indexing the whole graph.
	machines, _ := tx.FindMulti(engine.Type, engine.NV("Machine"))
	byDNSName := map[string][]*engine.Node{}
	byName := map[string][]*engine.Node{}
	machines.Iterate(func(m *engine.Node) bool {
		m.Attr(DNSHostname).Iterate(func(v engine.AttributeValue) bool {
			byDNSName[strings.ToLower(v.String())] = append(byDNSName[strings.ToLower(v.String())], m)
			return true
		})
		m.Attr(engine.Name).Iterate(func(v engine.AttributeValue) bool {
			byName[strings.ToLower(v.String())] = append(byName[strings.ToLower(v.String())], m)
			return true
		})
		return true
	})

	machines.Iterate(func(o *engine.Node) bool {
		host, controltype := o.OneAttrString(WUServer), "WSUS"
		if host == "" {
			host, controltype = o.OneAttrString(SCCMServer), "SCCM"
		}
		if host == "" {
			return true
		}
		// Try full DNS name, or fall back to just the name
		servers := byDNSName[strings.ToLower(host)]
		if len(servers) == 0 {
			servers = byName[strings.ToLower(host)]
		}
		if len(servers) == 0 {
			if net.ParseIP(host) != nil {
				ui.Warn().Msgf("Controlling %v server is referred to by IP address %v, unable to link it", controltype, host)
			}
			return true
		}
		for _, server := range servers {
			tx.EdgeBecause(server, o, EdgeControlsUpdates, Collected(controltype+" server setting"))
		}
		return true
	})
}

func init() {
	loader.AddProcessor(
		LinkSCCMProcessor,
		engine.Processor{
			Description: "Link SCCM and WSUS servers to controlled computers",
			Phase:       engine.AnalysisPhase,
			Needs:       []engine.Product{adanalyze.ProductMachines},
			Provides:    []engine.Product{ProductUpdateControl},
		})
	loader.AddProcessor(

		func(tx *engine.Tx) {
			var mut sync.Mutex
			sids := make(map[windowssecurity.SID][]*engine.Node)
			tx.IterateParallel(func(o *engine.Node) bool {
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
						tx.EdgeBecause(nodes[i], nodes[j], EdgeSIDCollision, engine.Source{Kind: adanalyze.SourceInference, Detail: "machines with the same local SID"})
					}
				}
			}

		},
		engine.Processor{
			Description: "Local SID collisions",
			Phase:       engine.AnalysisPhase,
			Provides:    []engine.Product{ProductSIDCollisions},
		})
}
