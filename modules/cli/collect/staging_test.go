package collect

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestStagedDirectoryReplacesTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "DC=example,DC=com")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(target, "old.adc"), "old")

	s, err := StageDirectory(target)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(s.Path) != root || s.Path == target {
		t.Fatalf("staging %v is not beside %v", s.Path, target)
	}
	writeTestFile(t, filepath.Join(s.Path, "new.adc"), "new")
	if readTestFile(t, filepath.Join(target, "old.adc")) != "old" {
		t.Fatal("target changed before commit")
	}
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.Abort(); err != nil {
		t.Fatal(err)
	}
	if readTestFile(t, filepath.Join(target, "new.adc")) != "new" {
		t.Fatal("new data missing")
	}
	if _, err := os.Stat(filepath.Join(target, "old.adc")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old data kept")
	}
	if entries, _ := os.ReadDir(root); len(entries) != 1 {
		t.Fatalf("staging left behind: %v", entries)
	}
}

func TestStagedDirectoryAbortKeepsTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "domain")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(target, "old.adc"), "old")
	s, err := StageDirectory(target)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(s.Path, "partial.adc"), "partial")
	if err := s.Abort(); err != nil {
		t.Fatal(err)
	}
	if readTestFile(t, filepath.Join(target, "old.adc")) != "old" {
		t.Fatal("abort changed the target")
	}
	if entries, _ := os.ReadDir(root); len(entries) != 1 {
		t.Fatalf("staging left behind: %v", entries)
	}
}

func TestStagedDirectoryNoOverwrite(t *testing.T) {
	*NoOverwrite = true
	defer func() { *NoOverwrite = false }()
	root := t.TempDir()
	target := filepath.Join(root, "domain")

	// A missing or empty target is allowed.
	s, err := StageDirectory(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(s.Path, "new.adc"), "new")
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// A target with data is refused before collection starts.
	if _, err := StageDirectory(target); !errors.Is(err, os.ErrExist) {
		t.Fatalf("non-empty target accepted: %v", err)
	}
	if readTestFile(t, filepath.Join(target, "new.adc")) != "new" {
		t.Fatal("target changed")
	}
}
