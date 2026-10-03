package analyze

import (
	"encoding/binary"
	"slices"
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	ad "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func serviceTestSID(sid windowssecurity.SID) []byte {
	return append([]byte{1, byte((len(sid) - 6) / 4)}, []byte(sid)...)
}

func serviceTestACL(aces ...engine.ACE) []byte {
	data := make([]byte, 8)
	data[0] = 2
	binary.LittleEndian.PutUint16(data[4:6], uint16(len(aces)))
	for _, ace := range aces {
		sid := serviceTestSID(ace.SID)
		entry := make([]byte, 8)
		entry[0], entry[1] = byte(ace.Type), byte(ace.ACEFlags)
		binary.LittleEndian.PutUint16(entry[2:4], uint16(8+len(sid)))
		binary.LittleEndian.PutUint32(entry[4:8], uint32(ace.Mask))
		data = append(data, append(entry, sid...)...)
	}
	binary.LittleEndian.PutUint16(data[2:4], uint16(len(data)))
	return data
}

func serviceTestDescriptor(owner windowssecurity.SID, acl []byte) []byte {
	data := make([]byte, 20)
	data[0] = 1
	binary.LittleEndian.PutUint16(data[2:4], uint16(engine.CONTROLFLAG_SELF_RELATIVE|engine.CONTROLFLAG_DACL_PRESENT))
	binary.LittleEndian.PutUint32(data[4:8], 20)
	data = append(data, serviceTestSID(owner)...)
	binary.LittleEndian.PutUint32(data[16:20], uint32(len(data)))
	return append(data, acl...)
}

func adminOnlyServiceFixture() localmachine.Service {
	acl := serviceTestACL(
		engine.ACE{Type: engine.ACETYPE_ACCESS_ALLOWED, SID: windowssecurity.AdministratorsSID, Mask: 0x10000000},
		engine.ACE{Type: engine.ACETYPE_ACCESS_ALLOWED, SID: windowssecurity.SystemSID, Mask: 0x10000000},
		engine.ACE{Type: engine.ACETYPE_ACCESS_ALLOWED, SID: windowssecurity.AuthenticatedUsersSID, Mask: engine.RIGHT_READ_CONTROL},
	)
	return localmachine.Service{Name: "SyntheticService", ImageExecutable: `C:\synthetic.exe`, AccountSID: windowssecurity.SystemSID.String(), ImageExecutableOwner: windowssecurity.SystemSID.String(), RegistryOwner: windowssecurity.AdministratorsSID.String(), ImageExecutableDACL: acl, RegistryDACL: acl, SecurityDescriptor: serviceTestDescriptor(windowssecurity.SystemSID, acl)}
}

func TestServiceAdminOnly(t *testing.T) {
	user := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1001")
	grant := func(mask engine.Mask) []byte {
		return serviceTestACL(engine.ACE{Type: engine.ACETYPE_ACCESS_ALLOWED, SID: user, Mask: mask})
	}
	for _, tc := range []struct {
		name string
		edit func(*localmachine.Service)
		skip bool
	}{
		{"admin-only", func(*localmachine.Service) {}, true},
		{"file-write", func(s *localmachine.Service) { s.ImageExecutableDACL = grant(engine.FILE_WRITE_DATA) }, false},
		{"file-owner", func(s *localmachine.Service) { s.ImageExecutableOwner = user.String() }, false},
		{"registry-owner", func(s *localmachine.Service) { s.RegistryOwner = user.String() }, false},
		{"registry-write", func(s *localmachine.Service) { s.RegistryDACL = grant(engine.KEY_SET_VALUE) }, false},
		{"service-config", func(s *localmachine.Service) {
			s.SecurityDescriptor = serviceTestDescriptor(windowssecurity.SystemSID, grant(engine.SERVICE_CHANGE_CONFIG))
		}, false},
		{"service-owner", func(s *localmachine.Service) { s.SecurityDescriptor = serviceTestDescriptor(user, s.RegistryDACL) }, false},
		{"generic-write", func(s *localmachine.Service) { s.RegistryDACL = grant(0x40000000) }, false},
		{"write-dacl", func(s *localmachine.Service) { s.RegistryDACL = grant(engine.RIGHT_WRITE_DACL) }, false},
		// Fields that were not collected are not evaluated; only data we
		// have is acted on, and it gives the graph no edges either.
		{"missing-file", func(s *localmachine.Service) { s.ImageExecutableDACL = nil }, true},
		{"missing-registry", func(s *localmachine.Service) { s.RegistryDACL = nil }, true},
		{"missing-service", func(s *localmachine.Service) { s.SecurityDescriptor = nil }, true},
		{"unknown-owner", func(s *localmachine.Service) { s.RegistryOwner = "" }, true},
		{"missing-service-file-write", func(s *localmachine.Service) {
			s.SecurityDescriptor = nil
			s.ImageExecutableDACL = grant(engine.FILE_WRITE_DATA)
		}, false},
		{"malformed-acl", func(s *localmachine.Service) { s.RegistryDACL = []byte{99, 0, 8, 0, 0, 0, 0, 0} }, false},
		{"null-dacl", func(s *localmachine.Service) { binary.LittleEndian.PutUint32(s.SecurityDescriptor[16:20], 0) }, false},
		{"inherit-only", func(s *localmachine.Service) {
			s.RegistryDACL = serviceTestACL(engine.ACE{Type: engine.ACETYPE_ACCESS_ALLOWED, SID: user, Mask: engine.KEY_SET_VALUE, ACEFlags: engine.ACEFLAG_INHERIT_ONLY_ACE})
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := adminOnlyServiceFixture()
			tc.edit(&s)
			if got := serviceAdminOnly(s, localAdministratorSID); got != tc.skip {
				t.Fatalf("skip=%v want %v", got, tc.skip)
			}
		})
	}
}

func TestImportServiceFiltering(t *testing.T) {
	g := engine.NewIndexedGraph()
	info := benchmarkCollectorInfo()
	service := adminOnlyServiceFixture()
	service.AccountSID = "S-1-5-21-4-5-6-1001"
	info.Services = []localmachine.Service{service}
	machine, err := importMachine(g, info)
	if err != nil {
		t.Fatal(err)
	}
	g.Iterate(func(n *engine.Node) bool {
		if n.Type() == engine.NodeTypeService || n.Type() == engine.NodeTypeExecutable || n.SID() == windowssecurity.ServiceNameToServiceSID(service.Name) {
			t.Error("admin-only service graph objects retained")
		}
		if n.Label() == "Users" || n.Label() == "Groups" || n.Label() == "Services" || n.Label() == "Scheduled Tasks" {
			t.Error("explorer container retained")
		}
		return true
	})
	account, found := g.Find(engine.ObjectSid, engine.NV(windowssecurity.MustParseStringSID(service.AccountSID)))
	if !found {
		t.Fatal("service account lost")
	}
	methods, _ := g.GetEdge(machine, account)
	if !methods.IsSet(EdgeHasServiceAccountCredentials) || !methods.IsSet(EdgeSessionService) {
		t.Fatal("machine credential/session links lost")
	}
	service.RegistryDACL = serviceTestACL(engine.ACE{Type: engine.ACETYPE_ACCESS_ALLOWED, SID: windowssecurity.AuthenticatedUsersSID, Mask: engine.KEY_SET_VALUE})
	info.Services = []localmachine.Service{service}
	g = engine.NewIndexedGraph()
	machine, err = importMachine(g, info)
	if err != nil {
		t.Fatal(err)
	}
	svc, found := g.FindTwo(engine.Name, engine.NV(service.Name), engine.Type, engine.NV("Service"))
	if !found {
		t.Fatal("modifiable service lost")
	}
	if svc.Parent() != machine {
		t.Fatal("service not parented to machine")
	}
	writer := enginetest.FindOrAddAdjacentSID(g, windowssecurity.AuthenticatedUsersSID, machine)
	methods, _ = g.GetEdge(writer, svc)
	if !methods.IsSet(EdgeRegistryWrite) {
		t.Fatal("takeover path lost")
	}
}

func TestSkippedServiceRetainsReferencedIdentities(t *testing.T) {
	g := engine.NewIndexedGraph()
	info := benchmarkCollectorInfo()
	omitted := adminOnlyServiceFixture()
	omitted.AccountSID = ""
	omitted.Account = `EXAMPLE\svc-account`
	retained := adminOnlyServiceFixture()
	retained.Name = "OtherService"
	identitySID := windowssecurity.ServiceNameToServiceSID(omitted.Name)
	retained.RegistryDACL = serviceTestACL(engine.ACE{Type: engine.ACETYPE_ACCESS_ALLOWED, SID: identitySID, Mask: engine.KEY_SET_VALUE})
	info.Services = []localmachine.Service{omitted, retained}
	machine, err := importMachine(g, info)
	if err != nil {
		t.Fatal(err)
	}
	account, found := g.Find(engine.DownLevelLogonName, engine.NV(omitted.Account))
	if !found {
		t.Fatal("name-only service account lost")
	}
	methods, _ := g.GetEdge(machine, account)
	if !methods.IsSet(ad.EdgeAuthenticatesAs) {
		t.Fatal("name-only execution identity path lost")
	}
	identity, found := g.FindAdjacentSID(identitySID, machine)
	if !found {
		t.Fatal("referenced service identity lost")
	}
	methods, _ = g.GetEdge(machine, identity)
	if !methods.IsSet(ad.EdgeAuthenticatesAs) {
		t.Fatal("referenced service identity path lost")
	}
	if _, found := g.FindTwo(engine.Name, engine.NV(omitted.Name), engine.Type, engine.NV("Service")); found {
		t.Fatal("redundant service retained")
	}
}

func TestLocalObjectsHaveNoExplorerContainers(t *testing.T) {
	g := engine.NewIndexedGraph()
	info := benchmarkCollectorInfo()
	s := adminOnlyServiceFixture()
	info.Shares = []localmachine.Share{{Name: "SyntheticShare", Path: `C:\synthetic`, DACL: s.SecurityDescriptor, PathDACL: s.RegistryDACL, PathOwner: s.RegistryOwner}}
	machine, err := importMachine(g, info)
	if err != nil {
		t.Fatal(err)
	}
	children := 0
	g.Iterate(func(n *engine.Node) bool {
		switch n.OneAttrString(engine.Type) {
		case "Person", "Group", "ScheduledTask", "Share":
			if n.Parent() != machine {
				t.Errorf("local %s not parented to machine", n.Type())
			}
			children++
		case "Container":
			t.Error("explorer container retained")
		}
		return true
	})
	if children < 4 {
		t.Fatal("fixture did not exercise local children")
	}
}

// TrustedInstaller counts as one of the machine's admins only where the
// TrustedInstaller service itself is admin-only.
func TestTrustedInstallerIsAdminWhereItsServiceIsAdminOnly(t *testing.T) {
	trustedInstallerOwned := adminOnlyServiceFixture()
	trustedInstallerOwned.ImageExecutableOwner = trustedInstallerSID.String()
	trustedInstaller := adminOnlyServiceFixture()
	trustedInstaller.Name = "TrustedInstaller"
	trustedInstaller.ImageExecutableOwner = trustedInstallerSID.String() // as on Windows

	if serviceAdminOnly(trustedInstallerOwned, machineAdmins(nil)) {
		t.Fatal("TrustedInstaller counted as admin without its service")
	}
	if !serviceAdminOnly(trustedInstallerOwned, machineAdmins([]localmachine.Service{trustedInstaller})) {
		t.Fatal("TrustedInstaller not counted as admin with an admin-only service")
	}
	user := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1001")
	open := trustedInstaller
	open.RegistryDACL = serviceTestACL(engine.ACE{Type: engine.ACETYPE_ACCESS_ALLOWED, SID: user, Mask: engine.KEY_SET_VALUE})
	if serviceAdminOnly(trustedInstallerOwned, machineAdmins([]localmachine.Service{open})) {
		t.Fatal("TrustedInstaller counted as admin although others can change its service")
	}
}

// An admin-only service is not a node: the machine lists it with its start
// type and authenticates as its account. A service someone else can change
// stays a node.
func TestAdminOnlyServiceIsInventoryAndAnEdge(t *testing.T) {
	info := syntheticMachine("HOST01", "S-1-5-21-111-222-333", "S-1-5-21-900-901-902-1101")
	adminOnly := adminOnlyServiceFixture()
	adminOnly.Start = 2
	open := adminOnlyServiceFixture()
	open.Name = "OpenService"
	open.ImageExecutableDACL = serviceTestACL(engine.ACE{Type: engine.ACETYPE_ACCESS_ALLOWED, SID: windowssecurity.AuthenticatedUsersSID, Mask: engine.FILE_WRITE_DATA})
	info.Services = localmachine.Services{adminOnly, open}
	g := engine.NewIndexedGraph()
	machine, err := importMachine(g, info)
	if err != nil {
		t.Fatal(err)
	}
	services := map[string]bool{}
	g.Iterate(func(n *engine.Node) bool {
		if n.Type() == engine.NodeTypeService {
			services[n.OneAttrString(engine.Name)] = true
		}
		return true
	})
	if services["SyntheticService"] || !services["OpenService"] {
		t.Fatalf("service nodes %v, want only the one others can change", services)
	}
	if !slices.Contains(machine.Attr(localmachine.InstalledServices).StringSlice(), "SyntheticService (automatic)") {
		t.Fatal("the admin-only service is missing from the machine's inventory")
	}
	runsAsSystem := false
	g.IterateEdges(machine, engine.Out, func(target *engine.Node, edges engine.EdgeBitmap) bool {
		runsAsSystem = runsAsSystem || (target.SID() == windowssecurity.SystemSID && edges.IsSet(ad.EdgeAuthenticatesAs))
		return true
	})
	if !runsAsSystem {
		t.Fatal("the machine does not authenticate as the admin-only service's account")
	}
}
