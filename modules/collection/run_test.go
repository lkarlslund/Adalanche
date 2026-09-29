package collection

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunVerification(t *testing.T) {
	RegisterValidator(AD, 99, func(r *Reader) error {
		for {
			_, _, err := r.Next()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
		}
	})
	for _, scenario := range []string{"complete", "interrupted", "failed", "missing", "replacement", "changed-plan"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			requested := map[string]string{"private-scope": "requested"}
			run, err := StartRun(dir, requested)
			if err != nil {
				t.Fatal(err)
			}
			requested["private-scope"] = "caller mutation"
			path := filepath.Join(dir, "private-name.adc")
			create := func() {
				w, err := Create(path, Header{Kind: AD, Schema: 99, Source: "private-source"})
				if err != nil {
					t.Fatal(err)
				}
				defer w.Abort()
				if err := w.Write("sample", []byte("private-payload")); err != nil {
					t.Fatal(err)
				}
				if err := w.Commit(Complete); err != nil {
					t.Fatal(err)
				}
			}
			create()
			if err := run.Record(path, AD, nil); err != nil {
				t.Fatal(err)
			}
			if scenario == "changed-plan" {
				run.manifest.Requested["extra"] = "changed"
			}
			if scenario != "interrupted" {
				var cause error
				if scenario == "failed" {
					cause = errors.New("private-failure-text")
				}
				if err := run.Finish(cause); !errors.Is(err, cause) {
					t.Fatalf("finish: %v", err)
				}
			}
			if scenario == "missing" || scenario == "replacement" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if scenario == "replacement" {
					create()
				}
			}
			summary, err := VerifyPath(dir)
			if (scenario == "complete") != (err == nil) {
				t.Fatalf("verification: %+v, %v", summary, err)
			}
			encoded, err := json.Marshal(summary)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "private-") {
				t.Fatal("summary leaked collected identifiers")
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ManifestSuffix) {
					f, err := os.Open(filepath.Join(dir, entry.Name()))
					if err != nil {
						t.Fatal(err)
					}
					r, err := NewReader(f, Manifest)
					if err != nil {
						t.Fatal(err)
					}
					_, payload, err := r.Next()
					if err != nil {
						t.Fatal(err)
					}
					if bytes.Contains(payload, []byte("private-failure-text")) {
						t.Fatal("manifest retained error text")
					}
					r.Close()
					_ = f.Close()
				}
			}
		})
	}
}

func TestRecordLengthOverflow(t *testing.T) {
	buffer := make([]byte, 7)
	binary.LittleEndian.PutUint16(buffer[:2], 1)
	binary.LittleEndian.PutUint32(buffer[2:6], ^uint32(0))
	r := Reader{buffer: buffer}
	if _, _, err := r.Next(); err == nil {
		t.Fatal("accepted overflowing record length")
	}
}

func TestFailedWriteCannotCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "failed.adc")
	w, err := Create(path, Header{Kind: AD, Schema: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	if err := w.Write("", nil); err == nil {
		t.Fatal("accepted invalid record")
	}
	if err := w.Commit(Complete); err == nil {
		t.Fatal("committed after write failure")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed output published")
	}
}

func TestRunMoveAndDropArtifacts(t *testing.T) {
	dir := t.TempDir()
	run, err := StartRun(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, StagingPrefix+"domain-1")
	run.manifest.Artifacts = []Artifact{
		{Path: StagingPrefix + "domain-1/objects.adc"},
		{Path: StagingPrefix + "domain-10/objects.adc"},
		{Path: "other.lmc"},
	}
	if err := run.MoveArtifacts(staging, filepath.Join(dir, "domain")); err != nil {
		t.Fatal(err)
	}
	if got := run.manifest.Artifacts[0].Path; got != "domain/objects.adc" {
		t.Fatalf("moved to %q", got)
	}
	if got := run.manifest.Artifacts[1].Path; got != StagingPrefix+"domain-10/objects.adc" {
		t.Fatalf("unrelated folder with the same prefix moved to %q", got)
	}
	run.DropArtifacts(filepath.Join(dir, StagingPrefix+"domain-10"))
	if len(run.manifest.Artifacts) != 2 || run.manifest.Artifacts[1].Path != "other.lmc" {
		t.Fatalf("drop: %+v", run.manifest.Artifacts)
	}
	if err := run.MoveArtifacts(filepath.Join(dir, ".."), dir); err == nil {
		t.Fatal("accepted a folder outside the run")
	}
}

func TestVerifySkipsStagingFolders(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, StagingPrefix+"domain-1")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "partial.adc"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	// Leftover temporary output is reported, never verified as a collection.
	summary, err := VerifyPath(dir)
	if err == nil {
		t.Fatal("abandoned staging folder passed verification")
	}
	if summary.Files != 0 || summary.TemporaryFiles != 1 {
		t.Fatalf("staging folder was verified: %+v", summary)
	}
}
