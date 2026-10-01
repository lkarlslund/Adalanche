package analyze

import (
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

// forestSites returns the site objects of the forest a domain belongs to.
// Sites live in CN=Sites,CN=Configuration,<forest root DN>.
func forestSites(ao *engine.IndexedGraph, domainDN string) []*engine.Node {
	domainDN = strings.ToLower(domainDN)
	sites, _ := ao.FindMulti(engine.ObjectClass, engine.NV("site"))
	var result []*engine.Node
	sites.Iterate(func(site *engine.Node) bool {
		dn := strings.ToLower(site.DN())
		_, root, found := strings.Cut(dn, ",cn=sites,cn=configuration,")
		if found && (domainDN == root || strings.HasSuffix(domainDN, ","+root)) {
			result = append(result, site)
		}
		return true
	})
	return result
}

// reportedSite returns the AD site name a local machine collection reports.
func reportedSite(machine *engine.Node) string {
	return machine.OneAttrString(localmachine.ADSite)
}

// machineSite finds the site object a machine belongs to: the site its own
// collection reports, or the only site when the forest has just one.
// Otherwise the site is unknown and nil is returned.
func machineSite(ao *engine.IndexedGraph, machine, computer *engine.Node) *engine.Node {
	sites := forestSites(ao, computer.OneAttrString(engine.DomainContext))
	if name := reportedSite(machine); name != "" {
		for _, site := range sites {
			if strings.EqualFold(site.OneAttrString(engine.Name), name) {
				return site
			}
		}
	}
	if len(sites) == 1 {
		return sites[0]
	}
	return nil
}
