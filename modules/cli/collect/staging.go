package collect

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/lkarlslund/adalanche/modules/collection"
)

// StagedDirectory collects into a temporary folder beside its target and
// replaces the target only when collection is complete. An interrupted or
// failed collection leaves the previous folder untouched.
type StagedDirectory struct {
	Target string
	// Path is where output is written until Commit.
	Path      string
	committed bool
}

// StageDirectory prepares a staged collection of target. With --nooverwrite
// a target folder that is not empty is an error.
func StageDirectory(target string) (*StagedDirectory, error) {
	if *NoOverwrite {
		if err := requireEmptyDirectory(target); err != nil {
			return nil, err
		}
	}
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return nil, err
	}
	path, err := os.MkdirTemp(parent, collection.StagingPrefix+filepath.Base(target)+"-*")
	if err != nil {
		return nil, err
	}
	return &StagedDirectory{Target: target, Path: path}, nil
}

// Commit replaces the target with the staged folder. The previous folder is
// moved aside first and restored if the staged folder cannot take its place.
func (s *StagedDirectory) Commit() error {
	if s.committed {
		return errors.New("staged directory already committed")
	}
	var previous string
	if _, err := os.Lstat(s.Target); err == nil {
		if *NoOverwrite {
			// Checked again: another collection may have filled it meanwhile.
			if err := requireEmptyDirectory(s.Target); err != nil {
				return err
			}
			if err := os.Remove(s.Target); err != nil {
				return err
			}
		} else {
			previous = s.Path + ".previous"
			if err := os.Rename(s.Target, previous); err != nil {
				return fmt.Errorf("moving previous data aside: %w", err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(s.Path, s.Target); err != nil {
		if previous != "" {
			err = errors.Join(err, os.Rename(previous, s.Target))
		}
		return fmt.Errorf("publishing collected data: %w", err)
	}
	s.committed = true
	if previous != "" {
		if err := os.RemoveAll(previous); err != nil {
			return fmt.Errorf("removing previous data from %v: %w", previous, err)
		}
	}
	return nil
}

// Abort discards the staged folder unless it was committed.
func (s *StagedDirectory) Abort() error {
	if s == nil || s.committed {
		return nil
	}
	return os.RemoveAll(s.Path)
}

func requireEmptyDirectory(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Readdirnames(1); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("%v is not empty and --nooverwrite is set: %w", path, os.ErrExist)
}
