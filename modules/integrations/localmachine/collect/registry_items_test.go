package collect

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/lkarlslund/adalanche/modules/basedata"
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
		make(basedata.CollectionResults),
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
		make(basedata.CollectionResults),
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

func TestRegistryOutcomesPreserveEmptyZeroAndFailures(t *testing.T) {
	outcomes := make(basedata.CollectionResults)
	cases := map[string]struct {
		value  any
		err    error
		status basedata.CollectionStatus
	}{
		registryItems[0]: {uint64(0), nil, basedata.CollectionCollected},
		registryItems[1]: {"", nil, basedata.CollectionCollected},
		registryItems[2]: {nil, fmt.Errorf("wrapped: %w", fs.ErrNotExist), basedata.CollectionNotFound},
		registryItems[3]: {nil, fs.ErrPermission, basedata.CollectionAccessDenied},
		registryItems[4]: {nil, errors.ErrUnsupported, basedata.CollectionUnsupported},
		registryItems[5]: {"partial discarded", errors.New("failed"), basedata.CollectionFailed},
	}
	values := collectRegistryItems(func(key string) (any, error) {
		if c, ok := cases[key]; ok {
			return c.value, c.err
		}
		return uint64(1), nil
	}, func(string) ([]string, error) { return nil, nil }, outcomes)
	for key, c := range cases {
		if got := outcomes["registry/value/"+key].Status; got != c.status {
			t.Fatalf("%s: %s", key, got)
		}
		if value, exists := values[key]; exists != (c.err == nil) || (exists && value != c.value) {
			t.Fatalf("incorrect value %q: %v", key, value)
		}
	}
	if outcomes["registry/subkeys/"+netbiosInterfacesRegistryPath].Status != basedata.CollectionCollected {
		t.Fatal("empty successful enumeration was lost")
	}
	if len(outcomes) != len(registryItems)+1 {
		t.Fatalf("missing operations: %d", len(outcomes))
	}
}

func TestPartialRegistryEnumerationRetainsFailureAndKnownValues(t *testing.T) {
	outcomes := make(basedata.CollectionResults)
	values := collectRegistryItems(func(string) (any, error) { return uint64(2), nil },
		func(string) ([]string, error) { return []string{"partial"}, fs.ErrPermission }, outcomes)
	if outcomes["registry/subkeys/"+netbiosInterfacesRegistryPath].Status != basedata.CollectionAccessDenied {
		t.Fatal("enumeration failure lost")
	}
	if _, ok := values[netbiosOptionRegistryItem("partial")]; !ok {
		t.Fatal("partial enumeration data lost")
	}
}

func assertNotContains(t *testing.T, items []string, forbidden string) {
	t.Helper()
	for _, item := range items {
		if item == forbidden {
			t.Fatalf("did not expect %q in %#v", forbidden, items)
		}
	}
}
