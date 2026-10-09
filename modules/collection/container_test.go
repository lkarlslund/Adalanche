package collection

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t testing.TB, records ...[]byte) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample.adc")
	w, err := Create(path, Header{Kind: AD, Schema: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	for _, record := range records {
		if err := w.Write("sample", record); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Commit("partial"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRoundTrip(t *testing.T) {
	payloads := [][]byte{nil, {0, 255, 1}, bytes.Repeat([]byte("binary\x00\xff"), 400000), []byte("last")}
	data := fixture(t, payloads...)
	r, err := NewReader(bytes.NewReader(data), AD)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, want := range payloads {
		kind, got, err := r.Next()
		if err != nil || kind != "sample" || !bytes.Equal(got, want) {
			t.Fatalf("record: kind=%q length=%d err=%v", kind, len(got), err)
		}
	}
	if _, _, err := r.Next(); err != io.EOF {
		t.Fatalf("footer: %v", err)
	}
	if r.Completion.Outcome != "partial" || r.Completion.Records != uint64(len(payloads)) {
		t.Fatalf("completion: %+v", r.Completion)
	}
	if _, _, err := r.Next(); err != io.EOF {
		t.Fatalf("second EOF: %v", err)
	}
}

func TestRejectsCorruptionAndTruncation(t *testing.T) {
	data := fixture(t, []byte("small payload"))
	for i := range data {
		if err := Validate(bytes.NewReader(data[:i]), AD); err == nil {
			t.Fatalf("accepted truncation at %d", i)
		}
		corrupt := bytes.Clone(data)
		corrupt[i] ^= 1
		if err := Validate(bytes.NewReader(corrupt), AD); err == nil {
			t.Fatalf("accepted bit flip at %d", i)
		}
	}
	if err := Validate(bytes.NewReader(append(bytes.Clone(data), 0)), AD); err == nil {
		t.Fatal("accepted trailing data")
	}
	if err := Validate(bytes.NewReader(data), Machine); err == nil {
		t.Fatal("accepted wrong kind")
	}
}

func TestEmptyAndMissingFooter(t *testing.T) {
	data := fixture(t)
	if err := Validate(bytes.NewReader(data), AD); err != nil {
		t.Fatal(err)
	}
	headerEnd := 12 + int(binary.LittleEndian.Uint32(data[8:12]))
	if err := Validate(bytes.NewReader(data[:headerEnd]), AD); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("missing footer: %v", err)
	}
}

func TestPublishLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.adc")
	w, err := Create(path, Header{Kind: AD, Schema: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published before commit")
	}
	w.Abort()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("abort cleanup: %v %v", entries, err)
	}
	w, err = Create(path, Header{Kind: AD, Schema: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit("complete"); err == nil {
		t.Fatal("overwrote competing output")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "existing" {
		t.Fatal("existing output changed")
	}
	if _, err := Create(path, Header{Kind: AD, Schema: 1}); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing collection: %v", err)
	}
}

func TestUnsupportedVersionAndOversizedHeader(t *testing.T) {
	data := fixture(t)
	data[7]++
	if err := Validate(bytes.NewReader(data), AD); err == nil {
		t.Fatal("accepted unsupported version")
	}
	data[7]--
	binary.LittleEndian.PutUint32(data[8:12], ^uint32(0))
	if err := Validate(bytes.NewReader(data), AD); err == nil {
		t.Fatal("accepted oversized header")
	}
}

func FuzzReader(f *testing.F) {
	f.Add(fixture(f, []byte("seed")))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) { _ = Validate(bytes.NewReader(data), AD) })
}

func BenchmarkRead(b *testing.B) {
	payloads := make([][]byte, 1000)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte("attribute-value"), 100)
	}
	data := fixture(b, payloads...)
	b.ReportAllocs()
	b.SetBytes(int64(len(payloads) * len(payloads[0])))
	b.ResetTimer()
	for b.Loop() {
		if err := Validate(bytes.NewReader(data), AD); err != nil {
			b.Fatal(err)
		}
	}
}

func TestReplaceExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.lmc")
	if err := os.WriteFile(path, []byte("previous"), 0600); err != nil {
		t.Fatal(err)
	}
	w, err := Create(path, Header{Kind: Machine, Schema: 2}, ReplaceExisting())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	if err := w.Write("sample", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "previous" {
		t.Fatal("replaced before commit")
	}
	if err := w.Commit(Complete); err != nil {
		t.Fatal(err)
	}
	w.Abort() // A deferred abort after publishing must not remove the result.
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := NewReader(f, Machine)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if kind, data, err := r.Next(); err != nil || kind != "sample" || string(data) != "new" {
		t.Fatalf("got %q %q %v", kind, data, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}
