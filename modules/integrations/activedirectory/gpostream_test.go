package activedirectory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/tinylib/msgp/msgp"
)

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }

type brokenReader struct{}

func (brokenReader) Read(b []byte) (int, error) { copy(b, "partial"); return 7, io.ErrUnexpectedEOF }

func TestPolicyFragmentStream(t *testing.T) {
	for _, partial := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "policy.gpc")
		w, err := CreateGPOCollection(path, GPOdump{})
		if err != nil {
			t.Fatal(err)
		}
		defer w.Abort()
		const size = 70 << 20
		file := GPOfileinfo{RelativePath: "/large", Size: size}
		if err := w.StartFile(file); err != nil {
			t.Fatal(err)
		}
		var source io.Reader = io.LimitReader(zeroReader{}, size)
		if partial {
			source = brokenReader{}
		}
		readErr, writeErr := w.CopyContents(context.Background(), source)
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		if partial != (readErr != nil) {
			t.Fatalf("read error: %v", readErr)
		}
		if err := w.EndFile(basedata.CollectionResults{"contents": basedata.CollectionResultFromError(readErr)}); err != nil {
			t.Fatal(err)
		}
		if err := w.Commit(basedata.CollectionResults{"enumeration": {Status: basedata.CollectionCollected}}); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		r, err := collection.NewReader(f, collection.GPO)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		var total, final int
		_, err = ScanGPOCollection(r, func(file GPOfileinfo, data []byte, end bool) error {
			if len(data) > policyFragmentSize {
				t.Fatal("oversized fragment")
			}
			total += len(data)
			if end {
				final++
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		want := size
		if partial {
			want = 7
		}
		if total != want || final != 1 {
			t.Fatalf("contents: %d, final events: %d", total, final)
		}
		if partial && r.Completion.Outcome != collection.Partial {
			t.Fatal("partial content reported complete")
		}
	}
}

func TestPolicyCancelAndUnfinishedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.gpc")
	w, err := CreateGPOCollection(path, GPOdump{})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	if err := w.StartFile(GPOfileinfo{RelativePath: "/file"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	readErr, writeErr := w.CopyContents(ctx, zeroReader{})
	if !errors.Is(readErr, context.Canceled) || writeErr != nil {
		t.Fatal("cancellation was lost")
	}
	if err := w.Commit(nil); err == nil {
		t.Fatal("committed unfinished file")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unfinished policy published")
	}
}

func TestFirstCutPolicySchemaStillReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.gpc")
	w, err := collection.Create(path, collection.Header{Kind: collection.GPO, Schema: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	if err := w.Write("policy", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(GPOfileinfo{RelativePath: "/binary", Size: 3})
	if err != nil {
		t.Fatal(err)
	}
	payload := msgp.AppendBytes(nil, metadata)
	for _, data := range [][]byte{nil, nil, {0, 255, 1}} {
		payload = msgp.AppendBytes(payload, data)
	}
	if err := w.Write("file", payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(collection.Unknown); err != nil {
		t.Fatal(err)
	}
	info, err := ReadGPOCollection(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Files) != 1 || !bytes.Equal(info.Files[0].Contents, []byte{0, 255, 1}) {
		t.Fatal("legacy payload changed")
	}
}
