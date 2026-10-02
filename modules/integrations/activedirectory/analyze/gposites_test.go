package analyze

import (
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/integrations/attrs"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

type siteScenario struct {
	sites        []string // site names; each links the GPO named "gpo-<site>"
	enforced     bool     // site links are enforced
	blockOU      bool     // the computer's OU blocks inheritance
	reportedSite string   // site the machine's collection reports
	collected    bool     // the machine's policy results were collected
	reported     bool     // the import linked "gpo-reported" to the machine
}

// affectedGPOs runs GPO targeting for one computer in a forest with the
// given sites and returns the names of the GPOs that affect its machine.
func affectedGPOs(t *testing.T, sc siteScenario) map[string]bool {
	t.Helper()
	const domainDN = "DC=example,DC=test"
	computerSID := mustSID(t, "S-1-5-21-1-2-3-1001")
	sd := engine.NV(securityDescriptorWithACEs(
		allowACE(windowssecurity.AuthenticatedUsersSID, engine.RIGHT_DS_READ_PROPERTY, uuid.Nil),
		allowACE(windowssecurity.AuthenticatedUsersSID, engine.RIGHT_DS_CONTROL_ACCESS, ExtendedRightApplyGroupPolicy),
	))
	gpo := func(name string) *engine.Node {
		return engine.NewNode(engine.Name, name, engine.Type, engine.NodeTypeGroupPolicyContainer.ValueString(),
			engine.DistinguishedName, "CN="+name+",CN=Policies,CN=System,"+domainDN, engine.DomainContext, domainDN, engine.NTSecurityDescriptor, sd)
	}
	options := "0"
	if sc.enforced {
		options = "2"
	}
	var nodes []*engine.Node
	for _, name := range sc.sites {
		g := gpo("gpo-" + name)
		nodes = append(nodes, g, engine.NewNode(engine.Name, name, engine.ObjectClass, "site",
			engine.DistinguishedName, "CN="+name+",CN=Sites,CN=Configuration,"+domainDN,
			activedirectory.GPLink, "[LDAP://"+g.DN()+";"+options+"]"))
	}
	reported := gpo("gpo-reported")
	ou := engine.NewNode(engine.DistinguishedName, "OU=Computers,"+domainDN)
	computer := engine.NewNode(engine.Type, engine.NodeTypeComputer.ValueString(), engine.ObjectSid, engine.NV(computerSID),
		engine.DistinguishedName, "CN=WS01,OU=Computers,"+domainDN, engine.DomainContext, domainDN)
	machine := engine.NewNode(engine.Type, ObjectTypeMachine.ValueString(), DomainJoinedSID, engine.NV(computerSID), attrs.DomainJoinedSID, engine.NV(computerSID))
	authenticated := engine.NewNode(engine.ObjectSid, engine.NV(windowssecurity.AuthenticatedUsersSID))

	graph := newADTestGraph(append(nodes, reported, ou, computer, machine, authenticated)...)
	if sc.blockOU {
		enginetest.Set(graph, ou, activedirectory.GPOptions, engine.NV("1"))
	}
	enginetest.ChildOf(graph, computer, ou)
	if sc.reportedSite != "" {
		enginetest.Set(graph, machine, localmachine.ADSite, engine.NV(sc.reportedSite))
	}
	if sc.collected {
		enginetest.Set(graph, machine, localmachine.GPOResultsCollected, engine.NV(true))
	}
	if sc.reported {
		enginetest.EdgeTo(graph, reported, machine, activedirectory.EdgeAffectedByGPO)
	}
	runTx(graph, addMachinesAffectedByGPO)

	got := map[string]bool{}
	graph.Edges(machine, engine.In).Iterate(func(source *engine.Node, eb engine.EdgeBitmap) bool {
		if eb.IsSet(activedirectory.EdgeAffectedByGPO) {
			got[source.OneAttrString(engine.Name)] = true
		}
		return true
	})
	return got
}

func TestSiteLinkedGPOs(t *testing.T) {
	for _, tt := range []struct {
		name string
		sc   siteScenario
		want []string
	}{
		{"single site applies to every machine", siteScenario{sites: []string{"hq"}}, []string{"gpo-hq"}},
		{"several sites without a reported site", siteScenario{sites: []string{"hq", "branch"}}, nil},
		{"reported site", siteScenario{sites: []string{"hq", "branch"}, reportedSite: "Branch"}, []string{"gpo-branch"}},
		{"blocked inheritance stops a site link", siteScenario{sites: []string{"hq"}, blockOU: true}, nil},
		{"an enforced site link passes a block", siteScenario{sites: []string{"hq"}, blockOU: true, enforced: true}, []string{"gpo-hq"}},
		{"reported results replace what the directory implies", siteScenario{sites: []string{"hq"}, collected: true, reported: true}, []string{"gpo-reported"}},
		{"reported results with nothing applied", siteScenario{sites: []string{"hq"}, collected: true}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := affectedGPOs(t, tt.sc)
			if len(got) != len(tt.want) {
				t.Fatalf("affected by %v, want %v", got, tt.want)
			}
			for _, name := range tt.want {
				if !got[name] {
					t.Fatalf("affected by %v, want %v", got, tt.want)
				}
			}
		})
	}
}
