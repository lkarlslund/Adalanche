package main

import (
	ldap "github.com/go-ldap/ldap/v3"
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
	result.DistinguishedName = r.DistinguishedName
	for name, values := range r.Attributes {
		if len(values) == 0 || (len(values) == 1 && values[0] == "") {
			continue
		}
		attribute := NewAttribute(name)
		for valindex, value := range values {
			// do we even want this?
			if !importall && attribute > MAX_IMPORTED {
				continue
			}

			// statistics
			attributesizes[attribute] += len(value)

			if attribute == NTSecurityDescriptor {
				if err := result.cacheSecurityDescriptor([]byte(value)); err != nil {
					log.Error().Msgf("Problem parsing security descriptor: %v", err)
				}

				continue
			}

			// mangling ObjectCategory
			// if attribute == ObjectCategory {
			// change CN=bla blabla,xxxxxxxxx -> bla blabla
			// value = value[3:strings.Index(value, ",")]
			// }

			// dedup
			if attribute <= MAX_DEDUP {
				values[valindex] = stringdedup.S(value)
			}
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
