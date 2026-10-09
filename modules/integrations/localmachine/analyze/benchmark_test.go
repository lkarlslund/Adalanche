package analyze

import (
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

func benchmarkCollectorInfo() localmachine.Info {
	return localmachine.Info{
		Machine: localmachine.Machine{
			Name:               "HOST01",
			LocalSID:           "S-1-5-21-111-222-333",
			Domain:             "EXAMPLE",
			IsDomainJoined:     false,
			WUServer:           "http://wsus.example.com:8530",
			SCCMLastValidMP:    "http://sccm.example.com",
			ProductName:        "Windows 11",
			ProductType:        "Workstation",
			Architecture:       "x64",
			DisplayVersion:     "23H2",
			BuildNumber:        "22631",
			MajorVersionNumber: 10,
		},
		Network: localmachine.NetworkInformation{
			InternetConnectivity: "Online",
			NetworkInterfaces: []localmachine.NetworkInterfaceInfo{
				{
					Name:       "Ethernet0",
					MACAddress: "aa:bb:cc:dd:ee:ff",
					Addresses:  []string{"10.0.0.10", "fe80::1"},
				},
			},
		},
		Users: localmachine.Users{
			{
				Name:            "alice",
				SID:             "S-1-5-21-111-222-333-1001",
				FullName:        "Alice Example",
				IsEnabled:       true,
				PasswordLastSet: time.Unix(1700000000, 0),
				LastLogon:       time.Unix(1700003600, 0),
			},
		},
		Groups: localmachine.Groups{
			{
				Name: "Administrators",
				SID:  "S-1-5-32-544",
				Members: []localmachine.Member{
					{Name: "alice", SID: "S-1-5-21-111-222-333-1001"},
				},
			},
		},
		Privileges: localmachine.Privileges{
			{Name: "SeBackupPrivilege", AssignedSIDs: []string{"S-1-5-32-544"}},
		},
		Tasks: []localmachine.RegisteredTask{
			{
				Name: "ExampleTask",
				Path: `\ExampleTask`,
				Definition: localmachine.TaskDefinition{
					Principal: localmachine.Principal{
						UserID: `EXAMPLE\alice`,
					},
					Actions: []localmachine.TaskAction{
						{Type: "Exec", Path: `C:\Windows\System32\cmd.exe`},
					},
				},
			},
		},
	}
}

func BenchmarkImportCollectorInfo(b *testing.B) {
	info := benchmarkCollectorInfo()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph := engine.NewIndexedGraph()
		if _, err := importMachine(graph, info); err != nil {
			b.Fatal(err)
		}
	}
}
