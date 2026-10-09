package engine

import (
	"reflect"

	"github.com/lkarlslund/adalanche/modules/ui"
)

// flexAttrValues is one attribute and its values from a flex list.
type flexAttrValues struct {
	attr   Attribute
	values AttributeValues
}

func expandFlexInit(flexinit ...any) []flexAttrValues {
	var (
		ignoreBlanks bool
		attribute    = NonExistingAttribute
		values       AttributeValues
		patches      []flexAttrValues
	)

	flush := func() {
		if attribute == NonExistingAttribute || (ignoreBlanks && len(values) == 0) {
			return
		}
		patches = append(patches, flexAttrValues{
			attr:   attribute,
			values: append(AttributeValues(nil), values...),
		})
		values = values[:0]
	}

	for _, item := range flexinit {
		if item == IgnoreBlanks {
			ignoreBlanks = true
			continue
		}
		if item == nil || (reflect.ValueOf(item).Kind() == reflect.Ptr && reflect.ValueOf(item).IsNil()) {
			if ignoreBlanks {
				continue
			}
			ui.Fatal().Msgf("Flex initialization with NIL value")
		}

		switch value := item.(type) {
		case *[]string:
			if value == nil {
				continue
			}
			if ignoreBlanks && len(*value) == 0 {
				continue
			}
			for _, s := range *value {
				if ignoreBlanks && s == "" {
					continue
				}
				values = append(values, NV(s))
			}
		case []string:
			if ignoreBlanks && len(value) == 0 {
				continue
			}
			for _, s := range value {
				if ignoreBlanks && s == "" {
					continue
				}
				values = append(values, NV(s))
			}
		case []AttributeValue:
			for _, attrValue := range value {
				if ignoreBlanks && attrValue.IsZero() {
					continue
				}
				values = append(values, attrValue)
			}
		case AttributeValues:
			for _, attrValue := range value {
				if ignoreBlanks && attrValue.IsZero() {
					continue
				}
				values = append(values, attrValue)
			}
		case Attribute:
			flush()
			attribute = value
		default:
			if reflect.ValueOf(item).Kind() == reflect.Ptr {
				item = reflect.ValueOf(item).Elem().Interface()
			}

			newValue := NV(item)
			if newValue.IsNil() || (ignoreBlanks && newValue.IsZero()) {
				if ignoreBlanks {
					continue
				}
				ui.Fatal().Msgf("Flex initialization with NIL value")
			}
			values = append(values, newValue)
		}
	}

	flush()
	return patches
}
