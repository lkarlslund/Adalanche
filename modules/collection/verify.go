package collection

import (
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/basedata"
)

type schemaKey struct {
	kind    Kind
	version uint32
}

var validators = struct {
	sync.RWMutex
	schemas map[schemaKey]func(*Reader) error
}{schemas: make(map[schemaKey]func(*Reader) error)}

// RegisterValidator is called by integrations during initialization.
func RegisterValidator(kind Kind, schema uint32, validate func(*Reader) error) {
	validators.Lock()
	defer validators.Unlock()
	validators.schemas[schemaKey{kind, schema}] = validate
}

func KindForPath(path string) Kind {
	switch strings.ToLower(filepath.Ext(path)) {
	case ADSuffix:
		return AD
	case GPOSuffix:
		return GPO
	case MachineSuffix:
		return Machine
	case ManifestSuffix:
		return Manifest
	default:
		return ""
	}
}

type VerifiedFile struct {
	Header       Header
	Completion   Completion
	Bytes        int64
	RecordCounts map[string]uint64
	Run          *RunManifest
}

func VerifyFile(path string) (VerifiedFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return VerifiedFile{}, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return VerifiedFile{}, err
	}
	if !stat.Mode().IsRegular() {
		return VerifiedFile{}, errors.New("collection is not a regular file")
	}
	r, err := NewReader(f, KindForPath(path))
	if err != nil {
		return VerifiedFile{}, err
	}
	defer r.Close()
	r.RecordCounts = make(map[string]uint64)
	result := VerifiedFile{Header: r.Header, Bytes: stat.Size()}
	if r.Header.Kind == Manifest {
		manifest, err := readRun(r)
		if err != nil {
			return VerifiedFile{}, err
		}
		result.Run = &manifest
	} else {
		validators.RLock()
		validate := validators.schemas[schemaKey{r.Header.Kind, r.Header.Schema}]
		validators.RUnlock()
		if validate == nil {
			return VerifiedFile{}, errors.New("no validator for collection schema")
		}
		if err := validate(r); err != nil {
			return VerifiedFile{}, err
		}
		if !r.done {
			return VerifiedFile{}, errors.New("validator did not consume complete collection")
		}
	}
	result.Completion, result.RecordCounts = r.Completion, r.RecordCounts
	return result, nil
}

// VerificationSummary deliberately excludes paths, IDs, sources and payloads.
// It describes files present, not whether all domains or machines were collected.
type VerificationSummary struct {
	Files                      int          `json:"files"`
	Kinds                      map[Kind]int `json:"kinds"`
	Bytes                      int64        `json:"bytes"`
	Records                    uint64       `json:"records"`
	Partial                    int          `json:"partial"`
	Unknown                    int          `json:"unknown"`
	Invalid                    int          `json:"invalid"`
	Unreadable                 int          `json:"unreadable"`
	UnfinishedRuns             int          `json:"unfinished_runs"`
	FailedRuns                 int          `json:"failed_runs"`
	MissingArtifacts           int          `json:"missing_artifacts"`
	MismatchedArtifacts        int          `json:"mismatched_artifacts"`
	UnverifiedExtensionRecords uint64       `json:"unverified_extension_records"`
	LegacyFiles                int          `json:"legacy_files_not_verified"`
	TemporaryFiles             int          `json:"temporary_files"`
}

func VerifyPath(path string) (VerificationSummary, error) {
	summary := VerificationSummary{Kinds: make(map[Kind]int)}
	files := make(map[string]VerifiedFile)
	plans, results := make(map[string]RunManifest), make(map[string]RunManifest)
	resultDirectories := make(map[string]string)
	err := filepath.WalkDir(path, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			summary.Unreadable++
			return nil
		}
		if entry.IsDir() {
			if IsStaging(entry.Name()) {
				summary.TemporaryFiles++ // An unfinished or abandoned output folder.
				return filepath.SkipDir
			}
			return nil
		}
		kind := KindForPath(path)
		if kind == "" {
			name := strings.ToLower(entry.Name())
			if IsStaging(name) && strings.HasSuffix(name, ".tmp") {
				summary.TemporaryFiles++
			}
			if strings.HasSuffix(name, ".objects.msgp.lz4") || strings.HasSuffix(name, ".gpodata.json") || strings.HasSuffix(name, ".localmachine.json") || strings.HasSuffix(name, ".localmachineplus.msgp.lz4") {
				summary.LegacyFiles++
			}
			return nil
		}
		summary.Files++
		if entry.Type()&os.ModeSymlink != 0 {
			summary.Invalid++
			return nil
		}
		verified, err := VerifyFile(path)
		if err != nil {
			summary.Invalid++
			return nil
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			summary.Invalid++
			return nil
		}
		files[absolute] = verified
		summary.Kinds[kind]++
		summary.Bytes += verified.Bytes
		summary.Records += verified.Completion.Records
		if kind != Manifest {
			if verified.Completion.Outcome == Partial {
				summary.Partial++
			}
			if verified.Completion.Outcome == Unknown {
				summary.Unknown++
			}
		}
		for record, count := range verified.RecordCounts {
			if strings.HasPrefix(record, "extension:") {
				summary.UnverifiedExtensionRecords += count
			}
		}
		if run := verified.Run; run != nil {
			if run.State == RunStarted {
				if _, exists := plans[run.ID]; exists {
					summary.Invalid++
				}
				plans[run.ID] = *run
			} else {
				if _, exists := results[run.ID]; exists {
					summary.Invalid++
				}
				results[run.ID], resultDirectories[run.ID] = *run, filepath.Dir(absolute)
				if run.State == RunFailed {
					summary.FailedRuns++
				}
			}
		}
		return nil
	})
	if err != nil {
		return summary, err
	}
	for id := range plans {
		if _, exists := results[id]; !exists {
			summary.UnfinishedRuns++
		}
	}
	for id, result := range results {
		plan, exists := plans[id]
		if !exists || !plan.Started.Equal(result.Started) || !maps.Equal(plan.Requested, result.Requested) {
			summary.Invalid++
		}
		for _, artifact := range result.Artifacts {
			if artifact.Result.Status != basedata.CollectionCollected {
				continue
			}
			file, exists := files[filepath.Join(resultDirectories[id], filepath.FromSlash(artifact.Path))]
			if !exists {
				summary.MissingArtifacts++
				continue
			}
			if file.Header.ID != artifact.ID || file.Header.Kind != artifact.Kind || file.Bytes != artifact.Bytes {
				summary.MismatchedArtifacts++
			}
		}
	}
	if summary.Files == 0 || summary.Invalid+summary.Unreadable+summary.UnfinishedRuns+summary.FailedRuns+summary.MissingArtifacts+summary.MismatchedArtifacts+summary.TemporaryFiles > 0 {
		return summary, errors.New("collection verification failed; see summary counts")
	}
	return summary, nil
}
