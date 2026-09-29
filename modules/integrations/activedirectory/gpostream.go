package activedirectory

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/tinylib/msgp/msgp"
)

const policyFragmentSize = 256 << 10

func init() {
	for _, schema := range []uint32{1, 2} {
		collection.RegisterValidator(collection.GPO, schema, func(r *collection.Reader) error {
			_, err := ScanGPOCollection(r, nil)
			return err
		})
	}
}

// GPOWriter writes one policy without retaining its file contents in memory.
// Every started file must be ended, including failed or partial reads.
type GPOWriter struct {
	container *collection.Writer
	outcome   collection.Outcome
	active    bool
	directory bool
	size      int64
	written   int64
	buffer    []byte
	err       error
}

func CreateGPOCollection(path string, info GPOdump, options ...collection.CreateOption) (*GPOWriter, error) {
	c, err := collection.Create(path, collection.Header{Kind: collection.GPO, Schema: 2, Collector: info.Common, Source: info.Path}, options...)
	if err != nil {
		return nil, err
	}
	info.Files = nil
	info.CollectionResults = nil // Final enumeration results follow the file records.
	data, err := json.Marshal(info)
	if err == nil {
		err = c.Write("policy", data)
	}
	if err != nil {
		c.Abort()
		return nil, err
	}
	return &GPOWriter{container: c, outcome: collection.Complete, buffer: make([]byte, policyFragmentSize)}, nil
}

func (w *GPOWriter) Abort() { w.container.Abort() }

func (w *GPOWriter) StartFile(file GPOfileinfo) error {
	if w.err != nil {
		return w.err
	}
	if w.active {
		return errors.New("previous policy file has not ended")
	}
	metadata := file
	metadata.Contents, metadata.DACL, metadata.OwnerSID = nil, nil, ""
	data, err := json.Marshal(metadata)
	if err != nil {
		w.err = err
		return err
	}
	payload := msgp.AppendBytes(nil, data)
	payload = msgp.AppendBytes(payload, []byte(file.OwnerSID))
	payload = msgp.AppendBytes(payload, file.DACL)
	w.err = w.container.Write("file-start", payload)
	if w.err != nil {
		return w.err
	}
	w.active, w.written = true, 0
	w.directory, w.size = file.IsDir, file.Size
	return nil
}

// CopyContents distinguishes read/acquisition failure from output failure. The
// former belongs in EndFile's results; an output failure must abort the artifact.
func (w *GPOWriter) CopyContents(ctx context.Context, r io.Reader) (readErr, writeErr error) {
	if !w.active {
		return nil, errors.New("no active policy file")
	}
	if w.directory {
		return nil, errors.New("directory cannot contain file data")
	}
	if w.err != nil {
		return nil, w.err
	}
	zeroReads := 0
	for {
		if err := ctx.Err(); err != nil {
			return err, nil
		}
		n, err := r.Read(w.buffer)
		if n < 0 || n > len(w.buffer) {
			return errors.New("invalid content reader count"), nil
		}
		if n > 0 {
			zeroReads = 0
			w.err = w.container.Write("file-data", w.buffer[:n])
			if w.err != nil {
				return nil, w.err
			}
			w.written += int64(n)
		}
		if err == io.EOF {
			return nil, nil
		}
		if err != nil {
			return err, nil
		}
		if n == 0 {
			zeroReads++
			if zeroReads >= 100 {
				return io.ErrNoProgress, nil
			}
		}
	}
}

type policyFileEnd struct {
	Bytes   int64
	Results basedata.CollectionResults
}

func (w *GPOWriter) EndFile(results basedata.CollectionResults) error {
	if w.err != nil {
		return w.err
	}
	if !w.active {
		return errors.New("no active policy file")
	}
	if results["contents"].Status == basedata.CollectionCollected && w.written != w.size {
		w.err = errors.New("collected content length does not match metadata")
		return w.err
	}
	data, err := json.Marshal(policyFileEnd{w.written, results})
	if err != nil {
		w.err = err
		return err
	}
	w.err = w.container.Write("file-end", data)
	if w.err != nil {
		return w.err
	}
	w.outcome = combinePolicyOutcome(w.outcome, results)
	w.active = false
	return nil
}

func (w *GPOWriter) Commit(results basedata.CollectionResults) error {
	if w.err != nil {
		return w.err
	}
	if w.active {
		return errors.New("policy file is unfinished")
	}
	data, err := json.Marshal(results)
	if err != nil {
		return err
	}
	if err := w.container.Write("policy-end", data); err != nil {
		return err
	}
	return w.container.Commit(combinePolicyOutcome(w.outcome, results))
}

func combinePolicyOutcome(outcome collection.Outcome, results basedata.CollectionResults) collection.Outcome {
	if len(results) == 0 && outcome == collection.Complete {
		outcome = collection.Unknown
	}
	for _, result := range results {
		switch result.Status {
		case basedata.CollectionCollected, basedata.CollectionNotRequested:
		case basedata.CollectionUnknown:
			if outcome == collection.Complete {
				outcome = collection.Unknown
			}
		default:
			outcome = collection.Partial
		}
	}
	return outcome
}

// ScanGPOCollection visits content fragments and then exactly one final event per
// file, including directories and failed reads. Content is valid until the next
// callback. The returned metadata contains final policy outcomes but no files.
// Callers must not admit visited data to analysis until this function succeeds.
func ScanGPOCollection(r *collection.Reader, visit func(GPOfileinfo, []byte, bool) error) (GPOdump, error) {
	if r.Header.Schema != 1 && r.Header.Schema != 2 {
		return GPOdump{}, errors.New("unsupported policy collection schema")
	}
	var info GPOdump
	var file GPOfileinfo
	seen, active, ended := false, false, false
	var total int64
	outcome := collection.Complete
	for {
		kind, payload, err := r.Next()
		if err == io.EOF {
			if !seen || active || (r.Header.Schema == 2 && !ended) {
				return GPOdump{}, errors.New("unfinished policy records")
			}
			if r.Header.Schema == 2 && r.Completion.Outcome != combinePolicyOutcome(outcome, info.CollectionResults) {
				return GPOdump{}, errors.New("policy outcome mismatch")
			}
			return info, nil
		}
		if err != nil {
			return GPOdump{}, err
		}
		if ended {
			return GPOdump{}, errors.New("records after policy completion")
		}
		if kind == "policy" {
			if seen {
				return GPOdump{}, errors.New("duplicate policy metadata")
			}
			if err := json.Unmarshal(payload, &info); err != nil {
				return GPOdump{}, err
			}
			if len(info.Files) != 0 {
				return GPOdump{}, errors.New("embedded policy files")
			}
			seen = true
			continue
		}
		if !seen {
			return GPOdump{}, errors.New("missing policy metadata")
		}
		switch {
		case kind == "file" && r.Header.Schema == 1, kind == "file-start" && r.Header.Schema == 2:
			if active {
				return GPOdump{}, errors.New("overlapping policy file records")
			}
			var fields [4][]byte
			count := 3
			if kind == "file" {
				count = 4
			}
			for i := range count {
				fields[i], payload, err = msgp.ReadBytesZC(payload)
				if err != nil {
					return GPOdump{}, err
				}
			}
			if len(payload) != 0 {
				return GPOdump{}, errors.New("trailing file metadata")
			}
			file = GPOfileinfo{}
			if err := json.Unmarshal(fields[0], &file); err != nil {
				return GPOdump{}, err
			}
			if len(file.Contents) != 0 || len(file.DACL) != 0 || file.OwnerSID != "" {
				return GPOdump{}, errors.New("embedded file data")
			}
			file.OwnerSID = windowssecurity.SID(string(fields[1]))
			if n := len(file.OwnerSID); n != 0 && (n < 6 || n > 66 || (n-6)%4 != 0) {
				return GPOdump{}, errors.New("invalid file owner identifier")
			}
			file.DACL = append([]byte(nil), fields[2]...)
			if kind == "file" {
				if visit != nil {
					if err := visit(file, fields[3], true); err != nil {
						return GPOdump{}, err
					}
				}
			} else {
				active, total = true, 0
			}
		case kind == "file-data" && r.Header.Schema == 2:
			if !active || file.IsDir || len(payload) == 0 || len(payload) > policyFragmentSize {
				return GPOdump{}, errors.New("invalid policy content fragment")
			}
			total += int64(len(payload))
			if visit != nil {
				if err := visit(file, payload, false); err != nil {
					return GPOdump{}, err
				}
			}
		case kind == "file-end" && r.Header.Schema == 2:
			if !active {
				return GPOdump{}, errors.New("unexpected policy file end")
			}
			var end policyFileEnd
			if err := json.Unmarshal(payload, &end); err != nil {
				return GPOdump{}, err
			}
			if total != end.Bytes {
				return GPOdump{}, errors.New("policy content length mismatch")
			}
			file.CollectionResults = end.Results
			if file.CollectionResults["contents"].Status == basedata.CollectionCollected && file.Size != total {
				return GPOdump{}, errors.New("collected file size mismatch")
			}
			outcome = combinePolicyOutcome(outcome, end.Results)
			if visit != nil {
				if err := visit(file, nil, true); err != nil {
					return GPOdump{}, err
				}
			}
			active = false
		case kind == "policy-end" && r.Header.Schema == 2:
			if active {
				return GPOdump{}, errors.New("unfinished policy file")
			}
			if err := json.Unmarshal(payload, &info.CollectionResults); err != nil {
				return GPOdump{}, err
			}
			ended = true
		default:
			return GPOdump{}, errors.New("unsupported policy record")
		}
	}
}
