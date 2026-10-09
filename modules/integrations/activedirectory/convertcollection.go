package activedirectory

import (
	"encoding/json"
	"io"
	"os"

	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/pierrec/lz4/v4"
	"github.com/tinylib/msgp/msgp"
)

func init() {
	collection.RegisterConverter(".objects.msgp.lz4", collection.AD, convertLegacyObjects)
	collection.RegisterConverter(".gpodata.json", collection.GPO, func(source, target string) error {
		info, err := ReadGPOCollection(source)
		if err != nil {
			return err
		}
		return WriteGPOCollection(target, info)
	})
}

func convertLegacyObjects(source, target string) error {
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	w, err := collection.Create(target, collection.Header{Kind: collection.AD, Schema: 1, Source: source,
		Scope: json.RawMessage(`{"method":"legacy-conversion","original_acquisition_coverage":"unknown"}`)})
	if err != nil {
		return err
	}
	defer w.Abort()
	objects := ObjectWriter{Container: w}
	reader := msgp.NewReaderSize(lz4.NewReader(f), 1<<20)
	for {
		var object RawObject
		err := object.DecodeMsg(reader)
		if msgp.Cause(err) == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err := objects.Write(&object); err != nil {
			return err
		}
	}
	return w.Commit(collection.Unknown)
}
