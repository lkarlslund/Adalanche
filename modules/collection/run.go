package collection

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/adalanche/modules/basedata"
)

type RunState string

const (
	RunStarted  RunState = "started"
	RunFinished RunState = "finished"
	RunFailed   RunState = "failed"
)

type Artifact struct {
	Path   string
	Kind   Kind
	ID     string `json:",omitempty"`
	Bytes  int64  `json:",omitempty"`
	Result basedata.CollectionResult
}

// RunManifest describes one command invocation, not the universe of domains or
// machines. A successful command does not establish complete acquisition coverage.
type RunManifest struct {
	ID        string
	State     RunState
	Started   time.Time
	Ended     time.Time `json:",omitempty"`
	Requested map[string]string
	Result    basedata.CollectionResult
	Artifacts []Artifact `json:",omitempty"`
}

type Run struct {
	directory string
	manifest  RunManifest
}

// StartRun publishes an immutable plan before acquisition. Finish writes a
// separate result; a missing result remains detectable after abrupt termination.
func StartRun(directory string, requested map[string]string) (*Run, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absolute, 0700); err != nil {
		return nil, err
	}
	r := &Run{directory: absolute, manifest: RunManifest{ID: rand.Text(), State: RunStarted, Started: time.Now().UTC(), Requested: maps.Clone(requested)}}
	if err := r.write("plan", Unknown); err != nil {
		return nil, err
	}
	return r, nil
}

// Record stores only artifact metadata and coded errors, never error text. A nil
// Run is the legacy no-op boundary, returning the original collection error.
func (r *Run) Record(path string, kind Kind, collectErr error) error {
	if r == nil || path == "" {
		return collectErr
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return errors.Join(collectErr, err)
	}
	relative, err := filepath.Rel(r.directory, absolute)
	if err != nil || !filepath.IsLocal(relative) {
		return errors.Join(collectErr, errors.New("artifact must be inside run directory"))
	}
	a := Artifact{Path: filepath.ToSlash(relative), Kind: kind, Result: basedata.CollectionResultFromError(collectErr)}
	if collectErr == nil {
		f, err := os.Open(path)
		if err == nil {
			var reader *Reader
			reader, err = NewReader(f, kind)
			if err == nil {
				a.ID = reader.Header.ID
				reader.Close()
				var stat os.FileInfo
				stat, err = f.Stat()
				if err == nil {
					a.Bytes = stat.Size()
				}
			}
			err = errors.Join(err, f.Close())
		}
		collectErr = err
		a.Result = basedata.CollectionResultFromError(err)
	}
	r.manifest.Artifacts = append(r.manifest.Artifacts, a)
	return collectErr
}

func (r *Run) Finish(collectErr error) error {
	if r == nil {
		return collectErr
	}
	if r.manifest.State != RunStarted {
		return errors.New("collection run already finished")
	}
	r.manifest.State = RunFinished
	outcome := Unknown
	if collectErr != nil {
		r.manifest.State, outcome = RunFailed, Partial
	}
	r.manifest.Ended = time.Now().UTC()
	r.manifest.Result = basedata.CollectionResultFromError(collectErr)
	return errors.Join(collectErr, r.write("result", outcome))
}

// MoveArtifacts rewrites recorded artifact paths after the folder from was
// renamed to to. Both folders must be inside the run directory.
func (r *Run) MoveArtifacts(from, to string) error {
	if r == nil {
		return nil
	}
	fromRel, err := r.relative(from)
	if err != nil {
		return err
	}
	toRel, err := r.relative(to)
	if err != nil {
		return err
	}
	for i, a := range r.manifest.Artifacts {
		if rest, ok := strings.CutPrefix(a.Path, fromRel+"/"); ok {
			r.manifest.Artifacts[i].Path = path.Join(toRel, rest)
		}
	}
	return nil
}

// DropArtifacts forgets artifacts recorded inside dir after it was discarded.
func (r *Run) DropArtifacts(dir string) {
	if r == nil {
		return
	}
	rel, err := r.relative(dir)
	if err != nil {
		return
	}
	r.manifest.Artifacts = slices.DeleteFunc(r.manifest.Artifacts, func(a Artifact) bool {
		return strings.HasPrefix(a.Path, rel+"/")
	})
}

func (r *Run) relative(dir string) (string, error) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(r.directory, absolute)
	if err != nil || !filepath.IsLocal(relative) {
		return "", errors.New("folder must be inside run directory")
	}
	return filepath.ToSlash(relative), nil
}

func (r *Run) manifestPath(stage string) string {
	return filepath.Join(r.directory, "run-"+r.manifest.ID+"."+stage+ManifestSuffix)
}

func (r *Run) write(stage string, outcome Outcome) error {
	path := r.manifestPath(stage)
	w, err := Create(path, Header{Kind: Manifest, Schema: 1})
	if err != nil {
		return err
	}
	defer w.Abort()
	data, err := json.Marshal(r.manifest)
	if err != nil {
		return err
	}
	if err := w.Write("run", data); err != nil {
		return err
	}
	return w.Commit(outcome)
}

func readRun(r *Reader) (RunManifest, error) {
	var manifest RunManifest
	if r.Header.Schema != 1 {
		return manifest, errors.New("unsupported manifest schema")
	}
	kind, data, err := r.Next()
	if err != nil {
		return manifest, err
	}
	if kind != "run" {
		return manifest, errors.New("missing run record")
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return RunManifest{}, err
	}
	if manifest.ID == "" || manifest.Started.IsZero() {
		return RunManifest{}, errors.New("invalid run identity")
	}
	switch manifest.State {
	case RunStarted:
		if !manifest.Ended.IsZero() || len(manifest.Artifacts) != 0 {
			return RunManifest{}, errors.New("invalid run plan")
		}
	case RunFinished, RunFailed:
		if manifest.Ended.Before(manifest.Started) {
			return RunManifest{}, errors.New("invalid run end time")
		}
	default:
		return RunManifest{}, errors.New("invalid run state")
	}
	for _, artifact := range manifest.Artifacts {
		local := filepath.FromSlash(artifact.Path)
		if !filepath.IsLocal(local) || artifact.Bytes < 0 {
			return RunManifest{}, errors.New("invalid artifact reference")
		}
		if artifact.Result.Status == basedata.CollectionCollected && (artifact.ID == "" || artifact.Bytes == 0) {
			return RunManifest{}, errors.New("missing artifact identity")
		}
	}
	if _, _, err := r.Next(); err != io.EOF {
		if err == nil {
			err = errors.New("extra manifest records")
		}
		return RunManifest{}, err
	}
	if manifest.State == RunFailed {
		if r.Completion.Outcome != Partial || manifest.Result.Status == basedata.CollectionCollected || manifest.Result.Status == basedata.CollectionUnknown {
			return RunManifest{}, errors.New("inconsistent failed run")
		}
	} else if r.Completion.Outcome != Unknown || (manifest.State == RunFinished && manifest.Result.Status != basedata.CollectionCollected) {
		return RunManifest{}, errors.New("inconsistent run completion")
	}
	return manifest, nil
}
