package collect

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCountCredentialFiles(t *testing.T) {
	root := t.TempDir()
	write := func(parts ...string) {
		t.Helper()
		path := filepath.Join(append([]string{root}, parts...)...)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("Credentials", "DFBE70A7E5CC19A398EBF1B96859CE5D")
	write("Credentials", "0AB1C2D3E4F5061728394A5B6C7D8E9F")
	write("Credentials", "sub", "ignored") // only files directly in the folder
	write("Vault", "4BF4C442-9B8A-41A0-B380-DD4A704DDB28", "Policy.vpol")
	write("Vault", "4BF4C442-9B8A-41A0-B380-DD4A704DDB28", "1A2B3C.vcrd")
	write("Vault", "4BF4C442-9B8A-41A0-B380-DD4A704DDB28", "4D5E6F.VCRD")
	write("Vault", "stray.vcrd") // not in a vault folder
	write("Protect", "S-1-5-21-1-2-3-1140", "6f2c4bd1-0e33-4a3e-9d55-2b1c6a8f4e10")
	write("Protect", "S-1-5-21-1-2-3-1140", "Preferred")
	if err := os.MkdirAll(filepath.Join(root, "EmptyCredentials"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		kind, dir string
		files     int
		exists    bool
	}{
		{"credentials", "Credentials", 2, true},
		{"vault", "Vault", 2, true},
		{"dpapi-keys", "Protect", 2, true},
		{"credentials", "EmptyCredentials", 0, true},
		{"credentials", "Missing", 0, false},
	} {
		files, exists, err := countCredentialFiles(c.kind, filepath.Join(root, c.dir))
		if err != nil || files != c.files || exists != c.exists {
			t.Errorf("%v %v: %v files, exists %v, %v; want %v, %v", c.kind, c.dir, files, exists, err, c.files, c.exists)
		}
	}
}

func TestFiletimeToTime(t *testing.T) {
	// 2024-01-02 03:04:05 UTC as a FILETIME, split as ProfileList keeps it.
	const ft = 133486382450000000
	got := filetimeToTime(ft>>32, ft&0xffffffff)
	if want := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC); !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if !filetimeToTime(0, 0).IsZero() {
		t.Error("zero FILETIME is not the zero time")
	}
}
