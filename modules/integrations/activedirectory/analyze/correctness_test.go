package analyze

import (
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/integrations/attrs"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestConstrainedDelegationWithoutProtocolTransition(t *testing.T) {
	for _, uac := range []int64{0, engine.UAC_TRUSTED_TO_AUTH_FOR_DELEGATION} {
		source := engine.NewNode(engine.Type, engine.NodeTypeUser.ValueString(), activedirectory.UserAccountControl, uac, activedirectory.MSDSAllowedToDelegateTo, "cifs/server.example.test")
		target := engine.NewNode(engine.Type, "Machine", DnsHostName, "server.example.test")
		graph := newADTestGraph(source, target)
		addConstrainedDelegationEdges(graph)
		requireEdgeSet(t, graph, source, target, edgeConstrainedDelegation)
	}
	source := engine.NewNode(engine.Type, engine.NodeTypeUser.ValueString(), activedirectory.UserAccountControl, int64(engine.UAC_TRUSTED_TO_AUTH_FOR_DELEGATION))
	target := engine.NewNode(engine.Type, "Machine", DnsHostName, "server.example.test")
	graph := newADTestGraph(source, target)
	addConstrainedDelegationEdges(graph)
	requireNoEdgeSet(t, graph, source, target, edgeConstrainedDelegation)
}

func TestGMSAPasswordReadAccess(t *testing.T) {
	sid := mustSID(t, "S-1-5-21-1-2-3-1001")
	allow := allowACE(sid, engine.RIGHT_DS_READ_PROPERTY, uuid.Nil)
	deny := allow
	deny.Type = engine.ACETYPE_ACCESS_DENIED
	inherit := allow
	inherit.ACEFlags = engine.ACEFLAG_INHERIT_ONLY_ACE
	for _, tt := range []struct {
		name string
		aces []engine.ACE
		want bool
	}{
		{"read", []engine.ACE{allow}, true},
		{"wrong mask", []engine.ACE{allowACE(sid, engine.RIGHT_DS_WRITE_PROPERTY, uuid.Nil)}, false},
		{"denied", []engine.ACE{deny, allow}, false},
		{"inherit only", []engine.ACE{inherit}, false},
		{"empty", nil, false},
		{"unrelated object right", []engine.ACE{allowACE(sid, engine.RIGHT_DS_READ_PROPERTY, AttributeMember)}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := engine.NewNode(engine.ObjectSid, sid)
			target := engine.NewNode(activedirectory.MSDSGroupMSAMembership, engine.NV(securityDescriptorWithACEs(tt.aces...)))
			graph := newADTestGraph(source, target)
			addGMSAPasswordReadEdges(graph)
			if tt.want {
				requireEdgeSet(t, graph, source, target, activedirectory.EdgeReadGMSAPassword)
			} else {
				requireNoEdgeSet(t, graph, source, target, activedirectory.EdgeReadGMSAPassword)
			}
		})
	}
}

func TestComputerPolicyMetadata(t *testing.T) {
	for _, tt := range []struct {
		name  string
		attrs []any
		want  bool
	}{
		{"unknown", nil, true},
		{"enabled", []any{gpoFlags, int64(0), gpoFunctionalityVersion, int64(2)}, true},
		{"user disabled", []any{gpoFlags, int64(1)}, true},
		{"computer disabled", []any{gpoFlags, int64(2)}, false},
		{"both disabled", []any{gpoFlags, int64(3)}, false},
		{"unsupported version", []any{gpoFunctionalityVersion, int64(1)}, false},
		{"empty", []any{gpoDirectoryVersion, int64(0), gpoFileVersion, int64(0)}, false},
		{"file version unknown", []any{gpoDirectoryVersion, int64(0)}, true},
		{"file version nonzero", []any{gpoDirectoryVersion, int64(0), gpoFileVersion, int64(1)}, true},
		{"directory version nonzero", []any{gpoDirectoryVersion, int64(1), gpoFileVersion, int64(0)}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gpo := engine.NewNode(tt.attrs...)
			if got := computerPolicyEnabled(gpo); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			gpoDN := "CN=Policy,CN=Policies,CN=System,DC=example,DC=test"
			gpo.Set(engine.DistinguishedName, engine.NV(gpoDN))
			sid := mustSID(t, "S-1-5-21-1-2-3-1001")
			ou := engine.NewNode(engine.DistinguishedName, "OU=Computers,DC=example,DC=test", activedirectory.GPLink, "[LDAP://"+gpoDN+";2]")
			computer := engine.NewNode(engine.ObjectSid, sid, engine.Type, "Computer", engine.DistinguishedName, "CN=Host,OU=Computers,DC=example,DC=test")
			machine := engine.NewNode(engine.Type, "Machine", attrs.DomainJoinedSID, sid)
			computer.ChildOf(ou)
			graph := newADTestGraph(gpo, ou, computer, machine)
			addMachinesAffectedByGPO(graph)
			edges, _ := graph.GetEdge(gpo, machine)
			if got := edges.IsSet(activedirectory.EdgeAffectedByGPO); got != tt.want {
				t.Fatalf("GPO edge %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGPOFileVersionImport(t *testing.T) {
	for _, tt := range []struct {
		name, contents string
		known          bool
		version        int64
	}{
		{"zero", "[General]\r\nVersion=0\r\n", true, 0},
		{"nonzero", "[general]\nversion=65537", true, 65537},
		{"missing", "[General]\n", false, 0},
		{"invalid", "[General]\nVersion=unknown", false, 0},
		{"overflow", "[General]\nVersion=4294967296", false, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			graph := newADTestGraph()
			err := ImportGPOInfo(activedirectory.GPOdump{GPOinfo: activedirectory.GPOinfo{Path: "policy", Files: []activedirectory.GPOfileinfo{{RelativePath: "/GPT.INI", Contents: []byte(tt.contents)}}}}, graph)
			if err != nil {
				t.Fatal(err)
			}
			node, ok := graph.Find(gPCFileSysPath, engine.NV("policy"))
			if !ok {
				t.Fatal("missing policy")
			}
			value, known := node.AttrInt(gpoFileVersion)
			if known != tt.known || known && value != tt.version {
				t.Fatalf("version %d known %v", value, known)
			}
		})
	}
}

func TestFailedGPOFileReadDoesNotEstablishEmptyVersion(t *testing.T) {
	graph := newADTestGraph()
	err := ImportGPOInfo(activedirectory.GPOdump{GPOinfo: activedirectory.GPOinfo{
		Path: "policy",
		Files: []activedirectory.GPOfileinfo{{
			RelativePath: "/gpt.ini", Contents: []byte("[General]\nVersion=0"),
			CollectionResults: basedata.CollectionResults{"contents": {Status: basedata.CollectionFailed}},
		}},
	}}, graph)
	if err != nil {
		t.Fatal(err)
	}
	node, found := graph.Find(gPCFileSysPath, engine.NV("policy"))
	if !found {
		t.Fatal("missing policy")
	}
	if node.HasAttr(gpoFileVersion) {
		t.Fatal("failed read must not establish a file version")
	}
}

func TestKerberoastSkipsDisabledAccounts(t *testing.T) {
	for _, tt := range []struct {
		name string
		uac  int64
		want bool
	}{
		{"enabled", engine.UAC_NORMAL_ACCOUNT, true},
		{"disabled", engine.UAC_NORMAL_ACCOUNT | engine.UAC_ACCOUNTDISABLE, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			authenticated := engine.NewNode(engine.ObjectSid, engine.NV(windowssecurity.AuthenticatedUsersSID))
			service := engine.NewNode(engine.Type, engine.NodeTypeUser.ValueString(), activedirectory.UserAccountControl, tt.uac,
				activedirectory.ServicePrincipalName, "http/web.example.test")
			graph := newADTestGraph(authenticated, service)
			if err := engine.Process(graph, "test", LoaderID, engine.BeforeMergeFinal); err != nil {
				t.Fatal(err)
			}
			edges, _ := graph.GetEdge(authenticated, service)
			if edges.IsSet(activedirectory.EdgeHasSPN) != tt.want || service.HasTag("kerberoast") != tt.want {
				t.Fatalf("HasSPN %v, tag %v, want %v", edges.IsSet(activedirectory.EdgeHasSPN), service.HasTag("kerberoast"), tt.want)
			}
		})
	}
}

func TestMembershipPropertySetGrantsAddMember(t *testing.T) {
	membershipSet := uuid.Must(uuid.FromString("bc0ac240-79a9-11d0-9020-00c04fc2d4cf"))
	writer := mustSID(t, "S-1-5-21-1-2-3-1001")
	schema := engine.NewNode(engine.SchemaIDGUID, engine.NV(AttributeMember), engine.AttributeSecurityGUID, engine.NV(membershipSet))
	principal := engine.NewNode(engine.ObjectSid, engine.NV(writer))
	group := engine.NewNode(engine.Type, engine.NodeTypeGroup.ValueString(),
		engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(allowACE(writer, engine.RIGHT_DS_WRITE_PROPERTY, membershipSet))))
	graph := newADTestGraph(schema, principal, group)
	if err := engine.Process(graph, "test", LoaderID, engine.BeforeMergeFinal); err != nil {
		t.Fatal(err)
	}
	requireEdgeSet(t, graph, principal, group, activedirectory.EdgeAddMember)
}
