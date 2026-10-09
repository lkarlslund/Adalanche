package activedirectory

import (
	"errors"
	"io"
	"sort"

	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/tinylib/msgp/msgp"
)

// ObjectWriter assigns file-local attribute IDs. Values remain binary, including
// unknown attributes and ranged attribute names; no engine types are serialized.
type ObjectWriter struct {
	Container  *collection.Writer
	attributes map[string]uint32
	buffer     []byte
}

func init() {
	collection.RegisterValidator(collection.AD, 1, func(r *collection.Reader) error {
		return ValidateObjects(&ObjectReader{Container: r})
	})
}

func (w *ObjectWriter) Write(object *RawObject) error {
	if w.attributes == nil {
		w.attributes = make(map[string]uint32)
	}
	names := make([]string, 0, len(object.Attributes))
	for name := range object.Attributes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, exists := w.attributes[name]; exists {
			continue
		}
		if name == "" || len(name) > 1024 || len(w.attributes) >= 65536 {
			return errors.New("invalid attribute definition")
		}
		id := uint32(len(w.attributes))
		w.buffer = msgp.AppendUint32(w.buffer[:0], id)
		w.buffer = msgp.AppendString(w.buffer, name)
		if err := w.Container.Write("attribute", w.buffer); err != nil {
			return err
		}
		w.attributes[name] = id
	}
	w.buffer = msgp.AppendString(w.buffer[:0], object.DistinguishedName)
	w.buffer = msgp.AppendMapHeader(w.buffer, uint32(len(names)))
	for _, name := range names {
		w.buffer = msgp.AppendUint32(w.buffer, w.attributes[name])
		values := object.Attributes[name]
		w.buffer = msgp.AppendArrayHeader(w.buffer, uint32(len(values)))
		for _, value := range values {
			w.buffer = msgp.AppendBytes(w.buffer, []byte(value))
		}
	}
	return w.Container.Write("object", w.buffer)
}

type ObjectReader struct {
	Container      *collection.Reader
	attributes     []string
	validationSeen map[string]struct{}
}

func (r *ObjectReader) Next() (*RawObject, error) {
	return r.next(true)
}

func (r *ObjectReader) next(retain bool) (*RawObject, error) {
	if r.Container.Header.Schema != 1 {
		return nil, errors.New("unsupported AD collection schema")
	}
	for {
		kind, payload, err := r.Container.Next()
		if err != nil {
			return nil, err
		}
		switch kind {
		case "attribute":
			id, rest, err := msgp.ReadUint32Bytes(payload)
			if err != nil {
				return nil, err
			}
			name, rest, err := msgp.ReadStringBytes(rest)
			if err != nil {
				return nil, err
			}
			if len(rest) != 0 || name == "" || len(name) > 1024 || id != uint32(len(r.attributes)) {
				return nil, errors.New("invalid attribute definition")
			}
			// The dictionary is bounded independently of the object's record size.
			if len(r.attributes) >= 65536 {
				return nil, errors.New("too many attribute definitions")
			}
			r.attributes = append(r.attributes, name)
		case "object":
			return r.decode(payload, retain)
		default:
			return nil, errors.New("unsupported AD record type")
		}
	}
}

func (r *ObjectReader) decode(payload []byte, retain bool) (*RawObject, error) {
	dn, rest, err := msgp.ReadStringZC(payload)
	if err != nil {
		return nil, err
	}
	n, rest, err := msgp.ReadMapHeaderBytes(rest)
	if err != nil {
		return nil, err
	}
	if uint64(n) > uint64(len(rest)/2) || int(n) > len(r.attributes) {
		return nil, errors.New("invalid object attribute count")
	}
	var object *RawObject
	if retain {
		object = &RawObject{DistinguishedName: string(dn), Attributes: make(map[string][]string, int(n))}
	} else {
		if r.validationSeen == nil {
			r.validationSeen = make(map[string]struct{}, int(n))
		}
		clear(r.validationSeen)
	}
	for range n {
		var id, count uint32
		id, rest, err = msgp.ReadUint32Bytes(rest)
		if err != nil {
			return nil, err
		}
		if uint64(id) >= uint64(len(r.attributes)) {
			return nil, errors.New("undefined object attribute")
		}
		name := r.attributes[id]
		if retain {
			if _, exists := object.Attributes[name]; exists {
				return nil, errors.New("duplicate object attribute")
			}
		} else {
			if _, exists := r.validationSeen[name]; exists {
				return nil, errors.New("duplicate object attribute")
			}
			r.validationSeen[name] = struct{}{}
		}
		count, rest, err = msgp.ReadArrayHeaderBytes(rest)
		if err != nil {
			return nil, err
		}
		if uint64(count) > uint64(len(rest)/2) {
			return nil, errors.New("invalid attribute value count")
		}
		var values []string
		if retain {
			values = make([]string, int(count))
		}
		for i := range count {
			var value []byte
			value, rest, err = msgp.ReadBytesZC(rest)
			if err != nil {
				return nil, err
			}
			if retain {
				values[i] = string(value)
			}
		}
		if retain {
			object.Attributes[name] = values
		}
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing object data")
	}
	return object, nil
}

// ValidateObjects also verifies type-specific records before analysis starts.
func ValidateObjects(reader *ObjectReader) error {
	for {
		_, err := reader.next(false)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
