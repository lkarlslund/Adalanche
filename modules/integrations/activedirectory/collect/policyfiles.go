package collect

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/lkarlslund/adalanche/modules/basedata"
	clicollect "github.com/lkarlslund/adalanche/modules/cli/collect"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// policyContents is a readable policy file together with a finalizer. The caller
// reads reader to completion (or copies it) and then calls finalize with any
// read error so the source can record the per-file contents result (and, for
// local files, verify the file did not change while being read).
type policyContents struct {
	reader   io.Reader
	finalize func(file *activedirectory.GPOfileinfo, readErr error)
}

// policySource yields the files of a single GPO, regardless of whether they live
// on a local/mounted filesystem or on a remote SMB share. walk visits the root
// and every descendant depth-first, passing each as a GPOfileinfo with its
// metadata and security already filled in, plus contents (nil for directories,
// skipped files, or when the file could not be opened). It returns the
// GPO-level enumeration results.
type policySource interface {
	walk(ctx context.Context, visit func(file *activedirectory.GPOfileinfo, contents *policyContents) error) (basedata.CollectionResults, error)
}

// localPolicySource walks a GPO's files on the local filesystem (a real SYSVOL
// path on Windows, or a mounted/overridden directory elsewhere).
type localPolicySource struct {
	info activedirectory.GPOdump
	root string
}

// walk opens content relative to a rooted directory handle. The visitor consumes
// a file before traversal continues; content errors remain acquisition data.
func (s localPolicySource) walk(ctx context.Context, visit func(file *activedirectory.GPOfileinfo, contents *policyContents) error) (basedata.CollectionResults, error) {
	info := s.info
	root := s.root
	results := make(basedata.CollectionResults)
	rooted, err := os.OpenRoot(root)
	if err != nil {
		results["enumeration"] = basedata.CollectionResultFromError(err)
		file := activedirectory.GPOfileinfo{CollectionResults: results}
		return results, visit(&file, nil)
	}
	defer rooted.Close()
	var visitorErr error
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		display := ""
		if rel != "." {
			display = string(filepath.Separator) + rel
		}
		file := activedirectory.GPOfileinfo{RelativePath: display, CollectionResults: make(basedata.CollectionResults)}
		if walkErr != nil {
			file.CollectionResults["enumeration"] = basedata.CollectionResultFromError(walkErr)
			results["enumeration"] = basedata.CollectionResultFromError(walkErr)
			visitorErr = visit(&file, nil)
			return visitorErr
		}
		file.IsDir = entry.IsDir()
		file.CollectionResults["enumeration"] = basedata.CollectionResultFromError(nil)
		stat, err := entry.Info()
		file.CollectionResults["metadata"] = basedata.CollectionResultFromError(err)
		if err == nil {
			file.Timestamp, file.Size = stat.ModTime(), stat.Size()
		}
		if entry.Type()&os.ModeSymlink != 0 {
			file.CollectionResults["security"] = basedata.CollectionResult{Status: basedata.CollectionUnsupported}
		} else if root == info.Path {
			file.OwnerSID, file.DACL, err = windowssecurity.GetOwnerAndDACL(path, windowssecurity.SE_FILE_OBJECT)
			file.CollectionResults["security"] = basedata.CollectionResultFromError(err)
		} else {
			file.CollectionResults["security"] = basedata.CollectionResult{Status: basedata.CollectionNotRequested}
		}
		file.CollectionResults["contents"] = basedata.CollectionResult{Status: basedata.CollectionNotRequested}
		var contents *os.File
		if !file.IsDir && !strings.HasSuffix(strings.ToLower(path), ".adm") && !strings.HasSuffix(strings.ToLower(path), ".admx") {
			if stat == nil || !stat.Mode().IsRegular() {
				err = errors.ErrUnsupported
			} else {
				contents, err = rooted.Open(rel)
				if err == nil {
					opened, statErr := contents.Stat()
					if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(stat, opened) {
						_ = contents.Close()
						contents = nil
						err = errors.New("policy file changed while opening")
					}
				}
			}
			file.CollectionResults["contents"] = basedata.CollectionResultFromError(err)
		}
		var payload *policyContents
		if contents != nil {
			handle := contents
			payload = &policyContents{
				reader: handle,
				finalize: func(file *activedirectory.GPOfileinfo, readErr error) {
					policyContentResult(file, handle, readErr)
				},
			}
		}
		visitorErr = visit(&file, payload)
		if contents != nil {
			_ = contents.Close()
		}
		return visitorErr
	})
	if visitorErr != nil {
		return results, visitorErr
	}
	if ctx.Err() != nil {
		return results, ctx.Err()
	}
	if walkErr != nil {
		results["enumeration"] = basedata.CollectionResultFromError(walkErr)
	}
	if _, exists := results["enumeration"]; !exists {
		results["enumeration"] = basedata.CollectionResultFromError(nil)
	}
	return results, nil
}

func policyContentResult(file *activedirectory.GPOfileinfo, contents *os.File, readErr error) {
	result := basedata.CollectionResultFromError(readErr)
	if readErr == nil {
		stat, err := contents.Stat()
		if err != nil {
			result = basedata.CollectionResultFromError(err)
		} else if stat.Size() != file.Size || !stat.ModTime().Equal(file.Timestamp) {
			result = basedata.CollectionResult{Status: basedata.CollectionFailed, ErrorCode: "changed_during_read"}
		}
	}
	file.CollectionResults["contents"] = result
}

func collectPolicyFiles(info activedirectory.GPOdump, src policySource) activedirectory.GPOdump {
	results, err := src.walk(context.Background(), func(file *activedirectory.GPOfileinfo, contents *policyContents) error {
		if contents != nil {
			var err error
			file.Contents, err = io.ReadAll(contents.reader)
			contents.finalize(file, err)
		}
		info.Files = append(info.Files, *file)
		return nil
	})
	if err != nil {
		results["enumeration"] = basedata.CollectionResultFromError(err)
	}
	info.CollectionResults = results
	return info
}

func writePolicyFiles(ctx context.Context, path string, info activedirectory.GPOdump, src policySource) error {
	w, err := activedirectory.CreateGPOCollection(path, info, clicollect.OutputOptions()...)
	if err != nil {
		return err
	}
	defer w.Abort()
	results, err := src.walk(ctx, func(file *activedirectory.GPOfileinfo, contents *policyContents) error {
		if err := w.StartFile(*file); err != nil {
			return err
		}
		if contents != nil {
			readErr, writeErr := w.CopyContents(ctx, contents.reader)
			if writeErr != nil {
				return writeErr
			}
			contents.finalize(file, readErr)
		}
		return w.EndFile(file.CollectionResults)
	})
	if err != nil {
		return err
	}
	return w.Commit(results)
}
