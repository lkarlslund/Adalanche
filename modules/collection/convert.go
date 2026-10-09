package collection

import (
	"errors"
	"strings"
	"sync"
)

type converter struct {
	suffix  string
	kind    Kind
	convert func(string, string) error
}

var converters = struct {
	sync.RWMutex
	entries []converter
}{}

func RegisterConverter(suffix string, kind Kind, convert func(string, string) error) {
	converters.Lock()
	defer converters.Unlock()
	converters.entries = append(converters.entries, converter{suffix, kind, convert})
}

// ConvertFile never modifies the source or replaces an existing destination.
// Conversion cannot recover coverage information missing from legacy data.
func ConvertFile(source, target string) error {
	converters.RLock()
	var selected converter
	for _, candidate := range converters.entries {
		if strings.HasSuffix(strings.ToLower(source), candidate.suffix) {
			selected = candidate
			break
		}
	}
	converters.RUnlock()
	if selected.convert == nil {
		return errors.New("unsupported conversion source format")
	}
	if KindForPath(target) != selected.kind {
		return errors.New("destination suffix does not match collection type")
	}
	return selected.convert(source, target)
}
