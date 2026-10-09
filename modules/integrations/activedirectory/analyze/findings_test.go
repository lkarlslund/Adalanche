package analyze

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
)

func TestParseGPLink(t *testing.T) {
	links, err := parseGPLink(" [LDAP://cn={A},cn=policies,cn=system,DC=example,DC=test;0][ldap://cn={B},cn=policies,cn=system,DC=example,DC=test;2] ")
	if err != nil {
		t.Fatal(err)
	}
	want := []gpLinkEntry{
		{"cn={A},cn=policies,cn=system,DC=example,DC=test", 0},
		{"cn={B},cn=policies,cn=system,DC=example,DC=test", 2},
	}
	if len(links) != len(want) || links[0] != want[0] || links[1] != want[1] {
		t.Fatalf("got %v, want %v", links, want)
	}
	if links, err := parseGPLink(""); err != nil || links != nil {
		t.Fatalf("empty: got %v, %v", links, err)
	}
	if _, err := parseGPLink("LDAP://cn={A};0"); err == nil {
		t.Fatal("missing brackets: expected an error")
	}
	links, err = parseGPLink("[garbage][LDAP://cn={A};1]")
	if err == nil || len(links) != 1 || links[0].options != 1 {
		t.Fatalf("partly invalid: got %v, %v", links, err)
	}
}

func TestBrokenGPOLinks(t *testing.T) {
	gpo := engine.NewNode(engine.DistinguishedName, "CN={A},CN=Policies,CN=System,DC=example,DC=test")
	ou := engine.NewNode(engine.DistinguishedName, "OU=Servers,DC=example,DC=test",
		activedirectory.GPLink, "[LDAP://cn={a},cn=policies,cn=system,DC=example,DC=test;0][LDAP://CN={GONE},CN=Policies,CN=System,DC=example,DC=test;0]")
	clean := engine.NewNode(engine.DistinguishedName, "OU=Clients,DC=example,DC=test",
		activedirectory.GPLink, "[LDAP://CN={A},CN=Policies,CN=System,DC=example,DC=test;0]")
	graph := newADTestGraph(gpo, ou, clean)
	runTx(graph, tagBrokenGPOLinks)

	if !ou.HasTag(TagGPOLinkBroken) {
		t.Fatal("expected the container linking a missing GPO to be tagged")
	}
	if broken := ou.Attr(BrokenGPLinks); broken.Len() != 1 || broken.First().String() != "CN={GONE},CN=Policies,CN=System,DC=example,DC=test" {
		t.Fatalf("got broken links %v", broken)
	}
	if clean.HasTag(TagGPOLinkBroken) || clean.HasAttr(BrokenGPLinks) {
		t.Fatal("container with only existing GPOs was tagged")
	}
}

func TestMissingDelegationTargets(t *testing.T) {
	source := engine.NewNode(engine.Type, engine.NodeTypeUser.ValueString(),
		activedirectory.MSDSAllowedToDelegateTo, []string{
			"cifs/server.example.test",            // machine
			"MSSQLSvc/sqlalias.example.test:1433", // SPN on a service account
			"http/gone.example.test",              // nothing
		})
	machine := engine.NewNode(engine.Type, "Machine", DnsHostName, "server.example.test")
	service := engine.NewNode(engine.Type, engine.NodeTypeUser.ValueString(),
		activedirectory.ServicePrincipalName, "mssqlsvc/sqlalias.example.test:1433")
	clean := engine.NewNode(engine.Type, engine.NodeTypeUser.ValueString(),
		activedirectory.MSDSAllowedToDelegateTo, "cifs/server.example.test")
	graph := newADTestGraph(source, machine, service, clean)
	runTx(graph, addConstrainedDelegationEdges)

	requireEdgeSet(t, graph, source, machine, edgeConstrainedDelegation)
	if !source.HasTag(TagDelegationTargetMissing) {
		t.Fatal("expected the delegating account to be tagged")
	}
	if missing := source.Attr(MissingDelegationTargets); missing.Len() != 1 || missing.First().String() != "http/gone.example.test" {
		t.Fatalf("got missing targets %v", missing)
	}
	if clean.HasTag(TagDelegationTargetMissing) {
		t.Fatal("account delegating to an existing machine was tagged")
	}
}

func TestMissingCertificateTemplates(t *testing.T) {
	service := engine.NewNode(engine.Type, engine.NodeTypePKIEnrollmentService.ValueString(),
		engine.DomainContext, "DC=example,DC=test",
		CertificateTemplates, []string{"User", "Retired"})
	template := engine.NewNode(engine.Name, "User", engine.ObjectClass, "pKICertificateTemplate",
		engine.DomainContext, "DC=example,DC=test")
	graph := newADTestGraph(service, template)
	runTx(graph, addCertificateTemplatePublishing)

	if !template.HasTag("published") {
		t.Fatal("expected the existing template to be published")
	}
	if !service.HasTag(TagCertificateTemplateMissing) {
		t.Fatal("expected the enrollment service to be tagged")
	}
	if missing := service.Attr(MissingCertificateTemplates); missing.Len() != 1 || missing.First().String() != "Retired" {
		t.Fatalf("got missing templates %v", missing)
	}
}
