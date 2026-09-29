package analyze

import (
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
)

func TestDCSyncCombinesOnlySameTrusteeRights(t *testing.T) {
	a := mustSID(t, "S-1-5-21-1-2-3-1001")
	b := mustSID(t, "S-1-5-21-1-2-3-1002")
	for _, tt := range []struct {
		name string
		aces []engine.ACE
		want bool
	}{
		{"split grants", []engine.ACE{allowACE(a, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChanges), allowACE(a, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChangesAll)}, true},
		{"incomplete", []engine.ACE{allowACE(a, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChanges)}, false},
		{"different trustees", []engine.ACE{allowACE(a, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChanges), allowACE(b, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChangesAll)}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			domain := engine.NewNode(engine.Type, engine.NodeTypeDomainDNS.ValueString(), engine.DistinguishedName, "DC=example,DC=test", activedirectory.SystemFlags, int64(1), engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(tt.aces...)))
			principal := engine.NewNode(engine.ObjectSid, engine.NV(a))
			graph := newADTestGraph(domain, principal)
			addDomainDNSDCSyncEdges(graph)
			service, found := graph.FindTwo(engine.Type, engine.NodeTypeCallableServicePoint.ValueString(), engine.Name, engine.NV("DCsync"))
			if !found {
				t.Fatal("missing DCSync service")
			}
			if tt.want {
				requireEdgeSet(t, graph, principal, service, activedirectory.EdgeCall)
			} else {
				requireNoEdgeSet(t, graph, principal, service, activedirectory.EdgeCall)
			}
		})
	}
}

func TestDCSyncServicesAreDomainScoped(t *testing.T) {
	a := mustSID(t, "S-1-5-21-1-2-3-1001")
	b := mustSID(t, "S-1-5-21-4-5-6-1001")
	first := engine.NewNode(engine.Type, engine.NodeTypeDomainDNS.ValueString(), engine.DistinguishedName, "DC=one,DC=test", activedirectory.SystemFlags, int64(1), engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(allowACE(a, engine.RIGHT_DS_CONTROL_ACCESS, uuid.Nil))))
	second := engine.NewNode(engine.Type, engine.NodeTypeDomainDNS.ValueString(), engine.DistinguishedName, "DC=two,DC=test", activedirectory.SystemFlags, int64(1), engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(allowACE(b, engine.RIGHT_DS_CONTROL_ACCESS, uuid.Nil))))
	principalA := engine.NewNode(engine.ObjectSid, engine.NV(a))
	principalB := engine.NewNode(engine.ObjectSid, engine.NV(b))
	graph := newADTestGraph(first, second, principalA, principalB)
	addDomainDNSDCSyncEdges(graph)
	addDomainDNSDCSyncEdges(graph)
	var services []*engine.Node
	graph.Iterate(func(o *engine.Node) bool {
		if o.Type() == engine.NodeTypeCallableServicePoint {
			services = append(services, o)
		}
		return true
	})
	if len(services) != 2 {
		t.Fatalf("got %d services, want 2", len(services))
	}
	for _, domain := range []*engine.Node{first, second} {
		service, found := graph.Find(engine.DistinguishedName, engine.NV("CN=DCsync,"+domain.DN()))
		if !found {
			t.Fatalf("no domain-specific service for %s", domain.DN())
		}
		requireEdgeSet(t, graph, domain, service, activedirectory.EdgeControls)
		if domain == first {
			requireEdgeSet(t, graph, principalA, service, activedirectory.EdgeCall)
			requireNoEdgeSet(t, graph, principalB, service, activedirectory.EdgeCall)
		} else {
			requireEdgeSet(t, graph, principalB, service, activedirectory.EdgeCall)
			requireNoEdgeSet(t, graph, principalA, service, activedirectory.EdgeCall)
		}
	}
}

func TestRBCDRequiresControlAccess(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	for _, tt := range []struct {
		name, sddl string
		want       bool
	}{
		{"control access", "D:(A;;CR;;;" + sid + ")", true},
		{"read only", "D:(A;;RP;;;" + sid + ")", false},
		{"no access", "D:(A;;0x0;;;" + sid + ")", false},
		{"inherit only", "D:(A;IO;CR;;;" + sid + ")", false},
		{"denied", "D:(D;;CR;;;" + sid + ")(A;;CR;;;" + sid + ")", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			acl, err := engine.ParseSDDL(tt.sddl)
			if err != nil {
				t.Fatal(err)
			}
			principal := engine.NewNode(engine.ObjectSid, engine.NV(mustSID(t, sid)))
			computer := engine.NewNode(engine.Type, engine.NodeTypeComputer.ValueString(), activedirectory.MSDSAllowedToActOnBehalfOfOtherIdentity, engine.NV(&engine.SecurityDescriptor{Control: engine.CONTROLFLAG_DACL_PRESENT, DACL: acl}))
			graph := newADTestGraph(principal, computer)
			addRBCDEdges(graph)
			if tt.want {
				requireEdgeSet(t, graph, principal, computer, EdgeRBCD)
			} else {
				requireNoEdgeSet(t, graph, principal, computer, EdgeRBCD)
			}
		})
	}
}

func TestDCSyncDeniedReplicationDoesNotCreateCall(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	acl, err := engine.ParseSDDL("D:(D;;CR;;;" + sid + ")(A;;CR;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	domain := engine.NewNode(
		engine.Type, engine.NodeTypeDomainDNS.ValueString(),
		engine.DistinguishedName, "DC=example,DC=test",
		activedirectory.SystemFlags, int64(1),
		engine.NTSecurityDescriptor, engine.NV(&engine.SecurityDescriptor{Control: engine.CONTROLFLAG_DACL_PRESENT, DACL: acl}),
	)
	principal := engine.NewNode(engine.ObjectSid, engine.NV(mustSID(t, sid)))
	graph := newADTestGraph(domain, principal)
	addDomainDNSDCSyncEdges(graph)
	service, found := graph.Find(engine.DistinguishedName, engine.NV("CN=DCsync,"+domain.DN()))
	if !found {
		t.Fatal("missing DCSync service")
	}
	requireNoEdgeSet(t, graph, principal, service, activedirectory.EdgeCall)
	requireNoEdgeSet(t, graph, principal, domain, activedirectory.EdgeDSReplicationGetChanges)
	requireNoEdgeSet(t, graph, principal, domain, activedirectory.EdgeDSReplicationGetChangesAll)
}
