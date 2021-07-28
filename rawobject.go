package main

import (
	"strings"

	ldap "github.com/lkarlslund/ldap/v3"
	"github.com/lkarlslund/stringdedup"
	"github.com/rs/zerolog/log"
)

//go:generate msgp

type RawObject struct {
	DistinguishedName string
	Attributes        map[string][]string
}

func (r *RawObject) init() {
	r.DistinguishedName = ""
	r.Attributes = make(map[string][]string)
}

func (r *RawObject) ToObject(importall bool) Object {
	var result Object
	result.init()
	result.DistinguishedName = stringdedup.S(r.DistinguishedName) // This is possibly repeated in member attributes, so dedup it
	for name, values := range r.Attributes {
		if len(values) == 0 || (len(values) == 1 && values[0] == "") {
			continue
		}
		attribute := NewAttribute(name)
		// do we even want this?
		if !importall && attribute > MAX_IMPORTED && !strings.HasPrefix(name, "_") {
			continue
		}
		for valindex, value := range values {
			// statistics
			attributesizes[attribute] += len(value)

			if attribute == NTSecurityDescriptor {
				if err := result.cacheSecurityDescriptor([]byte(value)); err != nil {
					log.Error().Msgf("Problem parsing security descriptor: %v", err)
				}
			}

			// dedup
			// if attribute <= MAX_DEDUP {
			// values[valindex] = value
			values[valindex] = stringdedup.S(value)
			// }
		}
		result.Attributes[attribute] = values
	}
	return result
}

func (r *RawObject) IngestLDAP(source *ldap.Entry) error {
	r.init()
	// if len(source.Attributes) == 0 {
	// 	return errors.New("No attributes in object, ignoring")
	// }
	r.DistinguishedName = source.DN
	for _, attr := range source.Attributes {
		r.Attributes[attr.Name] = attr.Values
	}
	return nil
}
