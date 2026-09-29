package collect

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "machine.json")
	if err := os.WriteFile(path, []byte("previous"), 0600); err != nil {
		t.Fatal(err)
	}

	failure := errors.New("interrupted")
	err := WriteFileAtomic(path, func(w io.Writer) error {
		io.WriteString(w, "partial")
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("got %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "previous" {
		t.Fatalf("failed write replaced the file with %q", data)
	}

	if err := WriteFileAtomic(path, func(w io.Writer) error {
		_, err := io.WriteString(w, "complete")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "complete" {
		t.Fatalf("got %q", data)
	}
	*NoOverwrite = true
	defer func() { *NoOverwrite = false }()
	if err := WriteFileAtomic(path, func(w io.Writer) error {
		_, err := io.WriteString(w, "replacement")
		return err
	}); !errors.Is(err, os.ErrExist) {
		t.Fatalf("--nooverwrite replaced the file: %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "complete" {
		t.Fatalf("got %q", data)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}
