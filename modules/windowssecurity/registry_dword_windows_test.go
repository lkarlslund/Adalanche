//go:build windows

package windowssecurity

import (
	"crypto/rand"
	"errors"
	"io/fs"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestReadRegistryDWORD(t *testing.T) {
	path := `Software\AdalancheCollectorTest-` + rand.Text()
	key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := key.Close(); err != nil {
			t.Error(err)
		}
		if err := registry.DeleteKey(registry.CURRENT_USER, path); err != nil {
			t.Error(err)
		}
	})
	for name, value := range map[string]uint32{"zero": 0, "revision": 1234, "maximum": ^uint32(0)} {
		if err := key.SetDWordValue(name, value); err != nil {
			t.Fatal(err)
		}
		got, err := ReadRegistryDWORD(`HKCU:\` + path + `\` + name)
		if err != nil || got != value {
			t.Errorf("%s: got %d, %v; want %d", name, got, err, value)
		}
	}
	if err := key.SetStringValue("string", "1234"); err != nil {
		t.Fatal(err)
	}
	if err := key.SetQWordValue("qword", 1234); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"string", "qword"} {
		if _, err := ReadRegistryDWORD(`HKCU:\` + path + `\` + name); !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("%s: expected unsupported, got %v", name, err)
		}
	}
	if _, err := ReadRegistryDWORD(`HKCU:\` + path + `\missing`); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
}
