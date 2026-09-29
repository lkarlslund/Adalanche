package smoke

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/pierrec/lz4/v4"
	"github.com/tinylib/msgp/msgp"
)

func TestCollectionCLI(t *testing.T) {
	root, work := repoRoot(t), t.TempDir()
	binary := filepath.Join(work, "adalanche")
	build := exec.Command("go", "build", "-o", binary, "./adalanche")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	source := filepath.Join(work, "SENSITIVE-NAME.objects.msgp.lz4")
	target := filepath.Join(work, "converted.adc")
	f, err := os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	compressed := lz4.NewWriter(f)
	writer := msgp.NewWriter(compressed)
	object := activedirectory.RawObject{DistinguishedName: "CN=SENSITIVE-NAME", Attributes: map[string][]string{"test": {"SENSITIVE-VALUE"}}}
	if err := object.EncodeMsg(writer); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	run := func(wantError bool, args ...string) collection.VerificationSummary {
		t.Helper()
		cmd := exec.Command(binary, args...)
		cmd.Dir = work
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if wantError != (err != nil) {
			t.Fatalf("command: %v\n%s\n%s", err, stdout.Bytes(), stderr.Bytes())
		}
		if bytes.Contains(stdout.Bytes(), []byte("SENSITIVE")) || bytes.Contains(stderr.Bytes(), []byte("SENSITIVE")) {
			t.Fatal("command exposed source identities or values")
		}
		var summary collection.VerificationSummary
		if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
			t.Fatalf("summary is not JSON: %v; %s", err, stdout.Bytes())
		}
		return summary
	}
	converted := run(false, "collections", "convert", source, target)
	if converted.Files != 1 || converted.Unknown != 1 {
		t.Fatalf("conversion summary: %+v", converted)
	}
	verified := run(false, "collections", "verify", work)
	if verified.Files != 1 || verified.LegacyFiles != 1 {
		t.Fatalf("verification summary: %+v", verified)
	}
	if _, err := os.Stat(filepath.Join(work, "data")); !os.IsNotExist(err) {
		t.Fatal("verification initialized collection output")
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, raw[:len(raw)-1], 0600); err != nil {
		t.Fatal(err)
	}
	bad := run(true, "collections", "verify", work)
	if bad.Invalid != 1 {
		t.Fatalf("invalid summary: %+v", bad)
	}
}
