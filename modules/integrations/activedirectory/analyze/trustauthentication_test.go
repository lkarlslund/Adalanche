package analyze

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestTrustAuthentication(t *testing.T) {
	for _, tt := range []struct {
		name       string
		direction  int64
		attributes int64
		collected  bool
		want       bool
	}{
		{"outbound forest trust", 3, 0x08, true, true},
		{"outbound only", 2, 0x08, true, true},
		{"inbound only", 1, 0x08, true, false},
		{"selective authentication", 3, 0x08 | 0x10, true, false},
		{"partner not collected", 3, 0x08, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			type domain struct {
				node, authenticatedUsers *engine.Node
				sid                      windowssecurity.SID
			}
			addDomain := func(g *engine.IndexedGraph, ncname, dnsroot, netbios, sid string) *domain {
				d := &domain{sid: mustSID(t, sid)}
				d.node = enginetest.AddNew(g,
					engine.Name, dnsroot,
					engine.Type, engine.NodeTypeDomainDNS.ValueString(),
					engine.ObjectClass, "domainDNS",
					engine.DistinguishedName, ncname,
					engine.DomainContext, ncname,
					engine.ObjectSid, engine.NV(d.sid),
				)
				enginetest.AddNew(g,
					engine.ObjectClass, "crossRef",
					NCName, ncname,
					DNSRoot, dnsroot,
					NetBIOSName, netbios,
				)
				runTx(g, func(tx *engine.Tx) {
					tx.FindOrAddAdjacentSID(windowssecurity.AuthenticatedUsersSID, d.node)
				})
				d.authenticatedUsers, _ = g.FindAdjacentSID(windowssecurity.AuthenticatedUsersSID, d.node)
				return d
			}

			g := newADTestGraph()
			trusting := addDomain(g, "DC=resources,DC=test", "resources.test", "RESOURCES", "S-1-5-21-100-200-300")
			partnerSID := mustSID(t, "S-1-5-21-400-500-600")
			var trusted *domain
			if tt.collected {
				trusted = addDomain(g, "DC=accounts,DC=test", "accounts.test", "ACCOUNTS", "S-1-5-21-400-500-600")
			}
			enginetest.AddNew(g,
				engine.Name, "accounts.test",
				engine.Type, engine.NodeTypeTrust.ValueString(),
				engine.DomainContext, "DC=resources,DC=test",
				activedirectory.TrustPartner, "accounts.test",
				activedirectory.TrustDirection, tt.direction,
				activedirectory.TrustAttributes, tt.attributes,
				activedirectory.SecurityIdentifier, engine.NV(partnerSID),
			)

			runTx(g, addTrustAuthentication)

			if trusted == nil {
				return
			}
			edges, _ := g.GetEdge(trusted.authenticatedUsers, trusting.authenticatedUsers)
			if got := edges.IsSet(activedirectory.EdgeMemberOfGroup); got != tt.want {
				t.Fatalf("trusted Authenticated Users member of trusting: got %v, want %v", got, tt.want)
			}
			if edges, _ := g.GetEdge(trusting.authenticatedUsers, trusted.authenticatedUsers); edges.IsSet(activedirectory.EdgeMemberOfGroup) {
				t.Fatal("trust added membership in the wrong direction")
			}
		})
	}
}
