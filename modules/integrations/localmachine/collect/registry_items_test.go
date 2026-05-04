package collect

import (
	"errors"
	"testing"
)

func TestRegistryCollectionItemsContainCorrectedKeys(t *testing.T) {
	items := registryCollectionItems(nil)

	assertContains(t, items, `HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity`)
	assertContains(t, items, `HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\UpdatePromptSettings`)
	assertNotContains(t, items, `HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuardEnableVirtualizationBasedSecurity`)
	assertNotContains(t, items, `HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\UpdaatePromptSettings`)
	assertNotContains(t, items, `HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*\NetbiosOptions`)
}

func TestRegistryCollectionItemsExpandNetbiosInterfaces(t *testing.T) {
	items := registryCollectionItems([]string{"Tcpip_{A}", "Tcpip_{B}"})

	assertContains(t, items, `HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{A}\NetbiosOptions`)
	assertContains(t, items, `HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{B}\NetbiosOptions`)
}

func TestCollectRegistryItemsUsesExpandedNetbiosInterfaces(t *testing.T) {
	readCalls := map[string]int{}

	results := collectRegistryItems(
		func(item string) (any, error) {
			readCalls[item]++
			if item == `HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{A}\NetbiosOptions` {
				return uint64(2), nil
			}
			return "ok", nil
		},
		func(item string) ([]string, error) {
			if item != netbiosInterfacesRegistryPath {
				t.Fatalf("unexpected subkey path: %s", item)
			}
			return []string{"Tcpip_{A}"}, nil
		},
	)

	if got := results[`HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{A}\NetbiosOptions`]; got != uint64(2) {
		t.Fatalf("expected expanded NetBIOS value, got %#v", got)
	}
	if readCalls[`HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*\NetbiosOptions`] != 0 {
		t.Fatal("wildcard NetBIOS path should never be read")
	}
}

func TestCollectRegistryItemsSkipsSubkeyEnumerationFailure(t *testing.T) {
	results := collectRegistryItems(
		func(item string) (any, error) { return item, nil },
		func(string) ([]string, error) { return nil, errors.New("boom") },
	)

	if _, found := results[`HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{A}\NetbiosOptions`]; found {
		t.Fatal("unexpected NetBIOS entry when interface enumeration failed")
	}
}

func assertContains(t *testing.T, items []string, expected string) {
	t.Helper()
	for _, item := range items {
		if item == expected {
			return
		}
	}
	t.Fatalf("expected %q in %#v", expected, items)
}

func assertNotContains(t *testing.T, items []string, forbidden string) {
	t.Helper()
	for _, item := range items {
		if item == forbidden {
			t.Fatalf("did not expect %q in %#v", forbidden, items)
		}
	}
}
