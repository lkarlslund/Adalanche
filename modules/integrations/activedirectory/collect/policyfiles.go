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

// walkPolicyFiles opens content relative to a rooted directory handle. The visitor
// consumes a file before traversal continues; content errors remain acquisition data.
func walkPolicyFiles(ctx context.Context, info activedirectory.GPOdump, root string, visit func(*activedirectory.GPOfileinfo, *os.File) error) (basedata.CollectionResults, error) {
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
		visitorErr = visit(&file, contents)
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

func collectPolicyFiles(info activedirectory.GPOdump, root string) activedirectory.GPOdump {
	results, err := walkPolicyFiles(context.Background(), info, root, func(file *activedirectory.GPOfileinfo, contents *os.File) error {
		if contents != nil {
			var err error
			file.Contents, err = io.ReadAll(contents)
			policyContentResult(file, contents, err)
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

func writePolicyFiles(ctx context.Context, path string, info activedirectory.GPOdump, root string) error {
	w, err := activedirectory.CreateGPOCollection(path, info, clicollect.OutputOptions()...)
	if err != nil {
		return err
	}
	defer w.Abort()
	results, err := walkPolicyFiles(ctx, info, root, func(file *activedirectory.GPOfileinfo, contents *os.File) error {
		if err := w.StartFile(*file); err != nil {
			return err
		}
		if contents != nil {
			readErr, writeErr := w.CopyContents(ctx, contents)
			if writeErr != nil {
				return writeErr
			}
			policyContentResult(file, contents, readErr)
		}
		return w.EndFile(file.CollectionResults)
	})
	if err != nil {
		return err
	}
	return w.Commit(results)
}
