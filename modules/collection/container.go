// Package collection stores typed collection records in a shared, versioned container.
// A valid footer confirms file integrity, not completeness of the acquired data.
package collection

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/lkarlslund/adalanche/modules/basedata"
)

type Kind string

const (
	AD              Kind = "ad"
	GPO             Kind = "gpo"
	Machine         Kind = "machine"
	Manifest        Kind = "manifest"
	ADSuffix             = ".adc"
	GPOSuffix            = ".gpc"
	MachineSuffix        = ".lmc"
	ManifestSuffix       = ".acm"
	chunkSize            = 1 << 20
	MaxRecordSize        = 64 << 20
	maxChunkSize         = MaxRecordSize + 1024
	maxMetadataSize      = 64 << 10
)

// StagingPrefix starts the names of temporary files and folders that hold
// output until it is complete. Loaders skip them.
const StagingPrefix = ".collection-"

// IsStaging reports whether a file or folder name is temporary output.
func IsStaging(name string) bool {
	return strings.HasPrefix(name, StagingPrefix)
}

// The final two bytes are the container major version, independent of payload schemas.
var magic = [8]byte{'A', 'D', 'A', 'L', 'C', 'T', 0, 2}

var ErrIncomplete = errors.New("collection has no valid completion footer")

type Outcome string

const (
	Complete Outcome = "complete"
	Partial  Outcome = "partial"
	Unknown  Outcome = "unknown"
)

type Header struct {
	Kind      Kind            `json:"kind"`
	Schema    uint32          `json:"schema"`
	ID        string          `json:"id"`
	Collector basedata.Common `json:"collector"`
	Source    string          `json:"source,omitempty"`
	Scope     json.RawMessage `json:"scope,omitempty"`
}

// Completion describes acquisition separately from the container's integrity.
// Outcome may be complete, partial or unknown. An omitted attribute is not proof
// of absence even when an enumeration completed successfully.
type Completion struct {
	Outcome Outcome   `json:"outcome"`
	Ended   time.Time `json:"ended"`
	Records uint64    `json:"records"`
	SHA256  string    `json:"sha256"`
}

func validOutcome(s Outcome) bool { return s == Complete || s == Partial || s == Unknown }

// Writer owns a private temporary file. Commit publishes without overwriting an
// existing collection. Call Abort with defer, including after a successful Commit.
// Writer is not safe for concurrent use.
type Writer struct {
	f          *os.File
	target     string
	encoder    *zstd.Encoder
	digest     hash.Hash
	buffer     []byte
	compressed []byte
	records    uint64
	err        error
	closed     bool
	replace    bool
}

// CreateOption changes how Create publishes a collection.
type CreateOption func(*Writer)

// ReplaceExisting publishes over an existing file at the target path instead
// of refusing it. The replacement is atomic: readers see the old or the new
// collection, never a partial one.
func ReplaceExisting() CreateOption {
	return func(w *Writer) { w.replace = true }
}

// Create starts a collection that Commit publishes at path. By default an
// existing file at path is an error.
func Create(path string, header Header, options ...CreateOption) (*Writer, error) {
	if header.Kind == "" || header.Schema == 0 {
		return nil, errors.New("collection kind and schema are required")
	}
	if header.ID == "" {
		header.ID = rand.Text()
	}
	if header.Collector.Collected.IsZero() {
		header.Collector = basedata.GetCommonData()
	}
	metadata, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	if len(metadata) > maxMetadataSize {
		return nil, errors.New("collection header too large")
	}
	var settings Writer
	for _, option := range options {
		option(&settings)
	}
	if _, err := os.Lstat(path); err == nil && !settings.replace {
		return nil, fmt.Errorf("collection already exists: %w", os.ErrExist)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), StagingPrefix+"*.tmp")
	if err != nil {
		return nil, err
	}
	w := &Writer{f: f, target: path, replace: settings.replace, digest: sha256.New(), buffer: make([]byte, 0, chunkSize)}
	w.encoder, err = zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderCRC(true), zstd.WithWindowSize(chunkSize))
	if err != nil {
		w.Abort()
		return nil, err
	}
	var size [4]byte
	binary.LittleEndian.PutUint32(size[:], uint32(len(metadata)))
	for _, b := range [][]byte{magic[:], size[:], metadata} {
		if err := w.write(b); err != nil {
			w.Abort()
			return nil, err
		}
	}
	return w, nil
}

func (w *Writer) write(b []byte) error {
	if w.err != nil {
		return w.err
	}
	n, err := w.f.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	w.err = err
	if err == nil {
		_, _ = w.digest.Write(b)
	}
	return err
}

// Write copies one typed payload. Payload schemas belong to their integrations.
func (w *Writer) Write(kind string, payload []byte) error {
	if w.closed {
		return os.ErrClosed
	}
	if w.err != nil {
		return w.err
	}
	if len(kind) == 0 || len(kind) > 255 || len(payload) > MaxRecordSize {
		w.err = errors.New("invalid collection record size or type")
		return w.err
	}
	size := 6 + len(kind) + len(payload)
	if len(w.buffer) > 0 && len(w.buffer)+size > chunkSize {
		if err := w.flush(); err != nil {
			return err
		}
	}
	w.buffer = binary.LittleEndian.AppendUint16(w.buffer, uint16(len(kind)))
	w.buffer = binary.LittleEndian.AppendUint32(w.buffer, uint32(len(payload)))
	w.buffer = append(w.buffer, kind...)
	w.buffer = append(w.buffer, payload...)
	w.records++
	if len(w.buffer) >= chunkSize {
		return w.flush()
	}
	return nil
}

func (w *Writer) flush() error {
	if len(w.buffer) == 0 {
		return w.err
	}
	w.compressed = w.encoder.EncodeAll(w.buffer, w.compressed[:0])
	var frame [9]byte
	frame[0] = 1
	binary.LittleEndian.PutUint32(frame[1:5], uint32(len(w.buffer)))
	binary.LittleEndian.PutUint32(frame[5:9], uint32(len(w.compressed)))
	if err := w.write(frame[:]); err != nil {
		return err
	}
	if err := w.write(w.compressed); err != nil {
		return err
	}
	w.buffer = w.buffer[:0]
	return nil
}

func (w *Writer) Commit(outcome Outcome) error {
	if w.closed {
		return os.ErrClosed
	}
	if !validOutcome(outcome) {
		return errors.New("invalid acquisition outcome")
	}
	if err := w.flush(); err != nil {
		return err
	}
	footer, err := json.Marshal(Completion{Outcome: outcome, Ended: time.Now().UTC(), Records: w.records, SHA256: hex.EncodeToString(w.digest.Sum(nil))})
	if err != nil {
		return err
	}
	var frame [9]byte
	frame[0] = 2
	binary.LittleEndian.PutUint32(frame[1:5], crc32.ChecksumIEEE(footer))
	binary.LittleEndian.PutUint32(frame[5:9], uint32(len(footer)))
	if err := w.write(frame[:]); err != nil {
		return err
	}
	if err := w.write(footer); err != nil {
		return err
	}
	if err := w.f.Sync(); err != nil {
		w.err = err
		return err
	}
	if err := w.f.Close(); err != nil {
		w.err = err
		return err
	}
	w.closed = true
	if w.replace {
		// Renaming in the same directory replaces the target atomically.
		return os.Rename(w.f.Name(), w.target)
	}
	// Linking in the same directory publishes atomically and refuses replacement.
	// If the filesystem cannot do this, retain no misleading final file.
	if err := os.Link(w.f.Name(), w.target); err != nil {
		return err
	}
	return nil
}

func (w *Writer) Abort() {
	if w.encoder != nil {
		_ = w.encoder.Close()
	}
	if !w.closed {
		_ = w.f.Close()
		w.closed = true
	}
	_ = os.Remove(w.f.Name())
}

type Reader struct {
	r          io.Reader
	decoder    *zstd.Decoder
	digest     hash.Hash
	Header     Header
	Completion Completion
	// RecordCounts and ValidateRecord are optional inspection hooks. Leave nil
	// for normal loading to avoid per-record accounting overhead.
	RecordCounts   map[string]uint64
	ValidateRecord func(string, []byte) error
	buffer         []byte
	decoded        []byte
	compressed     []byte
	records        uint64
	done           bool
	err            error
}

func NewReader(r io.Reader, expected Kind) (*Reader, error) {
	d := &Reader{r: r, digest: sha256.New()}
	var prefix [12]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, fmt.Errorf("collection header: %w", err)
	}
	if !bytes.Equal(prefix[:8], magic[:]) {
		return nil, errors.New("unsupported collection format")
	}
	size := binary.LittleEndian.Uint32(prefix[8:])
	if size == 0 || size > maxMetadataSize {
		return nil, errors.New("invalid collection header size")
	}
	metadata := make([]byte, size)
	if _, err := io.ReadFull(r, metadata); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(metadata, &d.Header); err != nil {
		return nil, err
	}
	if d.Header.Kind != expected || d.Header.Schema == 0 || d.Header.ID == "" {
		return nil, errors.New("unexpected collection kind or invalid schema")
	}
	_, _ = d.digest.Write(prefix[:])
	_, _ = d.digest.Write(metadata)
	var err error
	d.decoder, err = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxChunkSize), zstd.WithDecoderMaxWindow(chunkSize), zstd.WithDecodeAllCapLimit(true))
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (r *Reader) Close() { r.decoder.Close() }

// Next returns a payload valid until the next call. EOF is returned only after
// verifying the footer, record count, digest and absence of trailing bytes.
func (r *Reader) Next() (kind string, payload []byte, err error) {
	if r.err != nil {
		return "", nil, r.err
	}
	defer func() {
		if err != nil && err != io.EOF {
			r.err = err
		}
	}()
	if r.done {
		return "", nil, io.EOF
	}
	if len(r.buffer) == 0 {
		if err := r.frame(); err != nil {
			return "", nil, err
		}
	}
	if len(r.buffer) < 6 {
		return "", nil, errors.New("truncated collection record")
	}
	n := int(binary.LittleEndian.Uint16(r.buffer[:2]))
	length := binary.LittleEndian.Uint32(r.buffer[2:6])
	if n == 0 || n > 255 || length > MaxRecordSize || uint64(6+n)+uint64(length) > uint64(len(r.buffer)) {
		return "", nil, errors.New("invalid collection record")
	}
	size := int(length)
	kind = string(r.buffer[6 : 6+n])
	payload = r.buffer[6+n : 6+n+size]
	if r.ValidateRecord != nil {
		if err := r.ValidateRecord(kind, payload); err != nil {
			return "", nil, err
		}
	}
	if r.RecordCounts != nil {
		r.RecordCounts[kind]++
	}
	r.buffer = r.buffer[6+n+size:]
	r.records++
	return kind, payload, nil
}

func (r *Reader) frame() error {
	var frame [9]byte
	if _, err := io.ReadFull(r.r, frame[:]); err != nil {
		return fmt.Errorf("%w: %v", ErrIncomplete, err)
	}
	raw := binary.LittleEndian.Uint32(frame[1:5])
	size := binary.LittleEndian.Uint32(frame[5:9])
	if frame[0] == 2 {
		if size == 0 || size > maxMetadataSize {
			return errors.New("invalid collection footer size")
		}
		footer := make([]byte, size)
		if _, err := io.ReadFull(r.r, footer); err != nil {
			return fmt.Errorf("%w: %v", ErrIncomplete, err)
		}
		if crc32.ChecksumIEEE(footer) != raw {
			return errors.New("collection footer checksum failed")
		}
		if err := json.Unmarshal(footer, &r.Completion); err != nil {
			return err
		}
		if !validOutcome(r.Completion.Outcome) || r.Completion.Ended.IsZero() || r.Completion.Records != r.records || r.Completion.SHA256 != hex.EncodeToString(r.digest.Sum(nil)) {
			return errors.New("collection footer integrity check failed")
		}
		var trailing [1]byte
		if n, err := io.ReadFull(r.r, trailing[:]); n != 0 || err != io.EOF {
			return errors.New("unexpected data after collection footer")
		}
		r.done = true
		return io.EOF
	}
	if frame[0] != 1 || raw == 0 || raw > maxChunkSize || size == 0 || size > maxChunkSize+(1<<20) {
		return errors.New("invalid collection chunk")
	}
	if cap(r.compressed) < int(size) {
		r.compressed = make([]byte, size)
	} else {
		r.compressed = r.compressed[:size]
	}
	if _, err := io.ReadFull(r.r, r.compressed); err != nil {
		return fmt.Errorf("%w: %v", ErrIncomplete, err)
	}
	_, _ = r.digest.Write(frame[:])
	_, _ = r.digest.Write(r.compressed)
	if cap(r.decoded) < int(raw) {
		r.decoded = make([]byte, 0, int(raw))
	}
	decoded, err := r.decoder.DecodeAll(r.compressed, r.decoded[:0])
	if err != nil {
		return fmt.Errorf("collection chunk: %w", err)
	}
	if len(decoded) != int(raw) {
		return errors.New("collection chunk length mismatch")
	}
	r.buffer = decoded
	r.decoded = decoded
	return nil
}

// Validate scans a collection with bounded memory. Importers can rewind after
// validation to avoid admitting a corrupt or interrupted prefix into analysis.
func Validate(r io.Reader, kind Kind) error {
	d, err := NewReader(r, kind)
	if err != nil {
		return err
	}
	defer d.Close()
	for {
		_, _, err := d.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
