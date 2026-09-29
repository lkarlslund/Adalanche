package collect

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/lkarlslund/adalanche/modules/collection"
)

// WriteFileAtomic writes a file through a temporary file in the same folder
// and moves it into place. An interrupted collection never leaves a
// truncated or empty file under the final name. With --nooverwrite an
// existing file is an error and is left unchanged.
func WriteFileAtomic(path string, write func(io.Writer) error) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), collection.StagingPrefix+"*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	buffered := bufio.NewWriterSize(f, 1<<20)
	if err = write(buffered); err != nil {
		return err
	}
	if err = buffered.Flush(); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if *NoOverwrite {
		// Linking refuses an existing target atomically.
		err = os.Link(f.Name(), path)
		return errors.Join(err, os.Remove(f.Name()))
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return errors.Join(err, os.Remove(f.Name()))
	}
	return nil
}
