package collect

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	clicollect "github.com/lkarlslund/adalanche/modules/cli/collect"
	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/pierrec/lz4/v4"
	"github.com/tinylib/msgp/msgp"
)

// dumpWriter keeps legacy and container output behind one checked lifecycle.
type dumpWriter struct {
	file       *os.File
	compressed *lz4.Writer
	legacy     *msgp.Writer
	objects    *activedirectory.ObjectWriter
	outcome    collection.Outcome
	closed     bool
}

func newDumpWriter(options DumpOptions) (*dumpWriter, error) {
	w := &dumpWriter{outcome: collection.Unknown}
	if options.Method == "ldap" {
		w.outcome = collection.Complete
	}
	if options.WriteToFile == "" {
		return w, nil
	}
	if err := os.MkdirAll(filepath.Dir(options.WriteToFile), 0700); err != nil {
		return nil, err
	}
	if strings.HasSuffix(options.WriteToFile, collection.ADSuffix) {
		query := options.Query
		if query == "" {
			query = "(objectClass=*)"
		}
		scope, err := json.Marshal(struct {
			Method     string   `json:"method"`
			Base       string   `json:"base"`
			Filter     string   `json:"filter"`
			Attributes []string `json:"attributes"`
			Scope      int      `json:"scope"`
			PageSize   int      `json:"page_size"`
			NoSACL     bool     `json:"no_sacl"`
		}{options.Method, options.SearchBase, query, options.Attributes, options.Scope, options.ChunkSize, options.NoSACL})
		if err != nil {
			return nil, err
		}
		if options.Method == "snapshot" || options.Method == "database" {
			// Offline sources do not establish which live query collected them.
			scope, err = json.Marshal(struct {
				Method string `json:"method"`
			}{options.Method})
			if err != nil {
				return nil, err
			}
		}
		container, err := collection.Create(options.WriteToFile, collection.Header{Kind: collection.AD, Schema: 1, Source: options.Source, Scope: scope}, clicollect.OutputOptions()...)
		if err != nil {
			return nil, err
		}
		w.objects = &activedirectory.ObjectWriter{Container: container}
		return w, nil
	}
	var err error
	w.file, err = os.OpenFile(options.WriteToFile, clicollect.OutputFileFlags(), 0600)
	if err != nil {
		return nil, err
	}
	w.compressed = lz4.NewWriter(w.file)
	if err = w.compressed.Apply(lz4.BlockChecksumOption(true), lz4.ChecksumOption(true), lz4.CompressionLevelOption(lz4.Level9), lz4.ConcurrencyOption(-1)); err != nil {
		w.Abort()
		return nil, err
	}
	w.legacy = msgp.NewWriter(w.compressed)
	return w, nil
}

func (w *dumpWriter) Write(object *activedirectory.RawObject) error {
	if w.objects != nil {
		return w.objects.Write(object)
	}
	if w.legacy != nil {
		return object.EncodeMsg(w.legacy)
	}
	return nil
}

func (w *dumpWriter) Commit() error {
	if w.objects != nil {
		return w.objects.Container.Commit(w.outcome)
	}
	if w.legacy == nil {
		return nil
	}
	if err := w.legacy.Flush(); err != nil {
		return err
	}
	if err := w.compressed.Close(); err != nil {
		return err
	}
	if err := w.file.Sync(); err != nil {
		return err
	}
	w.closed = true
	return w.file.Close()
}

func (w *dumpWriter) Abort() {
	if w.objects != nil {
		w.objects.Container.Abort()
	}
	if w.file != nil && !w.closed {
		_ = w.file.Close()
		w.closed = true
	}
}

func removeFailedLegacyDump(path string) error {
	if strings.HasSuffix(path, collection.ADSuffix) {
		return nil
	}
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
