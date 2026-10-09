package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lkarlslund/adalanche/modules/basedata"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"golang.org/x/sys/windows/registry"
)

func TestAssessmentFileIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload.exe")
	if err := os.WriteFile(path, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	r := inspectAssessmentPath(path)
	if r.Result.Status != basedata.CollectionCollected || r.IdentityResult.Status != basedata.CollectionCollected || r.FileID == "" || r.VolumeSerial == "" || r.FinalPath == "" || r.ConfiguredPath != path || r.InspectionPath != path || r.Owner == "" {
		t.Fatalf("identity incomplete: %+v", r)
	}
	link := filepath.Join(filepath.Dir(path), "same-file.exe")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	other := inspectAssessmentPath(link)
	if other.Result.Status != basedata.CollectionCollected || other.FileID != r.FileID || other.VolumeSerial != r.VolumeSerial {
		t.Fatalf("hardlink identity mismatch: %+v", other)
	}
	missing := inspectAssessmentPath(path + ".absent")
	if missing.Result.Status != basedata.CollectionNotFound {
		t.Fatalf("missing = %+v", missing)
	}
}

func TestAssessmentReparsePoint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "payload"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "alias")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink fixture unavailable: %v", err)
	}
	for _, path := range []string{link, filepath.Join(link, "payload")} {
		r := inspectAssessmentPath(path)
		if r.Result.ErrorCode != "reparse_not_followed" || !r.ReparsePoint || r.ReparseAt != link || len(r.DACL) != 0 {
			t.Fatalf("reparse was not isolated: %+v", r)
		}
	}
}

func TestAssessmentRejectedPaths(t *testing.T) {
	for _, path := range []string{`relative.exe`, `\\server\share\file`, `\\.\pipe\fixture`, `C:\file:stream`, `%UNDEFINED_ADALANCHE_TEST%\file`} {
		r := inspectAssessmentPath(path)
		if r.Result.Status != basedata.CollectionUnsupported || len(r.DACL) != 0 {
			t.Fatalf("path %q = %+v", path, r)
		}
	}
}

func TestSystemDirectoryPathBoundary(t *testing.T) {
	if is64Bit || !os64Bit {
		t.Skip("WOW64-specific translation")
	}
	got := resolvepath(systemroot + `\System32Other\file`)
	if strings.Contains(strings.ToLower(got), `\sysnative`) {
		t.Fatal("translated an unrelated directory prefix")
	}
	got = resolvepath(systemroot + `\System32\file`)
	if !strings.HasPrefix(strings.ToLower(got), win32native+`\`) {
		t.Fatal("native system directory not selected")
	}
}

func TestRegistryPayloadView(t *testing.T) {
	if !os64Bit {
		t.Skip("requires a 64-bit OS")
	}
	path := systemroot + `\System32\fixture.dll`
	x86, err := registryPayloadPath(path, registry.WOW64_32KEY)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(x86), `\syswow64\`) {
		t.Fatalf("32-bit registration mapped to %q", x86)
	}
	native, err := registryPayloadPath(path, registry.WOW64_64KEY)
	if err != nil {
		t.Fatal(err)
	}
	if strings.EqualFold(native, x86) {
		t.Fatal("registry views collapsed")
	}
}

func TestAssessmentSelectionSkipsNativeJobs(t *testing.T) {
	oldOnly, oldSkip := assessmentOnly, assessmentSkip
	t.Cleanup(func() { assessmentOnly, assessmentSkip = oldOnly, oldSkip })
	assessmentOnly, assessmentSkip = []string{"certificate-services"}, nil
	var collectors []Collector
	for _, c := range registeredCollectors {
		if c.Stage >= StageAssessment {
			collectors = append(collectors, c)
		}
	}
	info := runCollectors(collectors, 4).Info
	a, err := lm.DecodeAssessment(info.AssessmentData)
	if err != nil {
		t.Fatal(err)
	}
	for name, category := range a.Categories {
		if category.Result.Status != basedata.CollectionNotRequested || len(category.Records) != 0 {
			t.Fatalf("skipped %s executed: %+v", name, category)
		}
		if info.CollectionResults["assessment/"+name].Status != basedata.CollectionNotRequested {
			t.Fatal("skip outcome not persisted")
		}
	}
	if len(a.Paths) != 0 {
		t.Fatal("path reads performed despite exclusion")
	}
}
