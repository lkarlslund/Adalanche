package activedirectory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/lkarlslund/adalanche/modules/collection"
)

func WriteGPOCollection(path string, info GPOdump) error {
	w, err := CreateGPOCollection(path, info)
	if err != nil {
		return err
	}
	defer w.Abort()
	for _, file := range info.Files {
		if err := w.StartFile(file); err != nil {
			return err
		}
		if file.IsDir {
			if len(file.Contents) != 0 {
				return errors.New("directory has content bytes")
			}
		} else {
			readErr, writeErr := w.CopyContents(context.Background(), bytes.NewReader(file.Contents))
			if readErr != nil {
				return readErr
			}
			if writeErr != nil {
				return writeErr
			}
		}
		if err := w.EndFile(file.CollectionResults); err != nil {
			return err
		}
	}
	return w.Commit(info.CollectionResults)
}

// ReadGPOCollection accepts legacy JSON and both container payload schemas.
// No paths are extracted, and failed reads return no partial policy.
func ReadGPOCollection(path string) (GPOdump, error) {
	f, err := os.Open(path)
	if err != nil {
		return GPOdump{}, err
	}
	defer f.Close()
	if !strings.HasSuffix(path, collection.GPOSuffix) {
		var info GPOdump
		if err := json.NewDecoder(f).Decode(&info); err != nil {
			return GPOdump{}, err
		}
		return info, nil
	}
	r, err := collection.NewReader(f, collection.GPO)
	if err != nil {
		return GPOdump{}, err
	}
	defer r.Close()
	return readGPORecords(r)
}

func readGPORecords(r *collection.Reader) (GPOdump, error) {
	var files []GPOfileinfo
	var contents []byte
	var total uint64
	info, err := ScanGPOCollection(r, func(file GPOfileinfo, data []byte, final bool) error {
		// The graph importer still needs in-memory contents. Fail explicitly rather
		// than exhausting memory; streaming verification has no aggregate limit.
		total += uint64(len(data))
		if total > 256<<20 {
			return errors.New("policy exceeds the 256 MiB in-memory import budget; artifact can still be stream-verified")
		}
		contents = append(contents, data...)
		if final {
			file.Contents = contents
			files = append(files, file)
			contents = nil
		}
		return nil
	})
	if err != nil {
		return GPOdump{}, err
	}
	info.Files = files
	return info, nil
}
