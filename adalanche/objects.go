package main

import (
	"strings"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

type Objects struct {
	Domain        string // tld
	DomainNetbios string
	Base          string // dc=blabla ,dc=com

	idcounter uint64 // Unique ID +1 to assign to Object added to this collection if it's zero

	asarray []*Object

	index map[Attribute]map[interface{}]*Object

	typecount [OBJECTTYPEMAX]int

	// classmap map[string]*Object // top, user, person -> schema object
}

func (os *Objects) Init(ios *Objects) {
	os.index = make(map[Attribute]map[interface{}]*Object)
	// os.lookupcounter = make([]uint64)
	if ios != nil {
		os.Base = ios.Base
		os.Domain = ios.Domain
		os.DomainNetbios = ios.DomainNetbios
		os.idcounter = ios.idcounter
		// for attribute, _ := range ios.index {
		// 	os.index[attribute] = make(map[interface{}]*Object)
		// }
	}
}

func (os *Objects) AddIndex(attribute Attribute) {
	// create index
	os.index[attribute] = make(map[interface{}]*Object)
	// add all existing stuff to index
	for _, o := range os.asarray {
		value := o.OneAttr(attribute)
		if value != nil {
			// If it's a string, lowercase it before adding to index, we do the same on lookups
			if vs, ok := value.(AttributeValueString); ok {
				os.index[attribute][strings.ToLower(string(vs))] = o
			} else {
				os.index[attribute][value.Raw()] = o
			}
		}
	}
}

func (os *Objects) Filter(evaluate func(o *Object) bool) *Objects {
	var result Objects
	result.Init(os)

	for _, object := range os.asarray {
		if evaluate(object) {
			result.Add(object)
		}
	}
	return &result
}

func (os *Objects) Add(obs ...*Object) {
	for _, o := range obs {
		if o.ID == 0 {
			os.idcounter++
			o.ID = os.idcounter
		}

		// Do chunked extensions for speed
		if len(os.asarray) == cap(os.asarray) {
			newarray := make([]*Object, len(os.asarray), len(os.asarray)+1024)
			copy(newarray, os.asarray)
			os.asarray = newarray
		}
		// Add this to the iterator array
		os.asarray = append(os.asarray, o)

		for attribute := range os.index {
			value := o.OneAttr(attribute)
			if value != nil {
				// If it's a string, lowercase it before adding to index, we do the same on lookups
				if vs, ok := value.(AttributeValueString); ok {
					value = AttributeValueString(strings.ToLower(string(vs)))
				}
				existing, dupe := os.index[attribute][value.Raw()]
				if dupe {
					log.Warn().Msgf("Duplicate index %v value %v when trying to add %v, already exists as %v, skipping import", attribute.String(), value.String(), o.DN(), existing.DN())
				} else {
					os.index[attribute][value.Raw()] = o
				}
			}
		}

		// Statistics
		os.typecount[o.Type()]++
	}
}

func (os Objects) Statistics() [OBJECTTYPEMAX]int {
	return os.typecount
}

func (os Objects) AsArray() []*Object {
	return os.asarray
}

func (os *Objects) Find(attribute Attribute, value AttributeValue) (o *Object, found bool) {
	index, found := os.index[attribute]
	if !found {
		os.AddIndex(attribute)
		index = os.index[attribute]
	}

	var result *Object

	// If it's a string, lowercase it before adding to index, we do the same on lookups
	if vs, ok := value.(AttributeValueString); ok {
		result, found = index[strings.ToLower(string(vs))]
	} else {
		result, found = index[value.Raw()]
	}

	return result, found
}

func (os *Objects) Parent(o *Object) (*Object, bool) {
	var dn = o.DN()
	for {
		firstcomma := strings.Index(dn, ",")
		if firstcomma == -1 {
			return nil, false // At the top
		}
		if firstcomma > 0 {
			if dn[firstcomma-1] == '\\' {
				// False alarm, strip it an go on
				dn = dn[firstcomma+1:]
				continue
			}
		}
		dn = dn[firstcomma+1:]
		break
	}
	return os.Find(DistinguishedName, AttributeValueString(dn))
}

func (os *Objects) Subordinates(o *Object) *Objects {
	return os.Filter(func(o2 *Object) bool {
		candidatedn := o2.DN()
		mustbesubordinateofdn := o.DN()
		if len(candidatedn) <= len(mustbesubordinateofdn) {
			return false
		}
		if !strings.HasSuffix(o2.DN(), o.DN()) {
			return false
		}
		prefixlength := len(candidatedn) - len(mustbesubordinateofdn)
		escapedcommas := strings.Count(candidatedn[:prefixlength], "\\,")
		commas := strings.Count(candidatedn[:prefixlength], ",")
		return commas-escapedcommas == 1
	})
}

func (os *Objects) FindOrAddSID(s SID) *Object {
	o, found := os.Find(ObjectSid, AttributeValueSID(s))
	if found {
		return o
	}
	u, _ := uuid.NewV4()
	o = NewObject()
	o.SetAttr(DistinguishedName, AttributeValueString("CN="+s.String()+",CN=synthetic"))
	o.SetAttr(Name, AttributeValueString(s.String()))
	o.SetAttr(ObjectGUID, AttributeValueGUID(u))
	o.SetAttr(ObjectSid, AttributeValueSID(s))
	log.Debug().Msgf("Adding unknown SID %v as %v", s, o.DN())
	os.Add(o)
	return o
}

func (os *Objects) FindGUID(g uuid.UUID) (o *Object, found bool) {
	return os.Find(ObjectGUID, AttributeValueGUID(g))
}
