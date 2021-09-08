package main

import (
	"errors"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

type Objects struct {
	Domain        string // tld
	DomainNetbios string
	Base          string // dc=blabla ,dc=com

	idcounter uint64 // Unique ID +1 to assign to Object added to this collection if it's zero

	asarray   []*Object
	objectmap map[*Object]struct{}
	dnmap     map[string]*Object
	sidmap    map[SID]*Object
	guidmap   map[uuid.UUID]*Object
	typecount [OBJECTTYPEMAX]int

	classmap map[string]*Object // top, user, person -> schema object
}

func (os *Objects) Init(ios *Objects) {
	if ios != nil {
		os.Base = ios.Base
		os.Domain = ios.Domain
		os.DomainNetbios = ios.DomainNetbios
		os.idcounter = ios.idcounter
	}
	os.objectmap = make(map[*Object]struct{})
	os.dnmap = make(map[string]*Object)
	os.sidmap = make(map[SID]*Object)
	os.guidmap = make(map[uuid.UUID]*Object)

	os.classmap = make(map[string]*Object)
}

func (os *Objects) Filter(evaluate func(o *Object) bool) *Objects {
	var result Objects
	result.Init(os)

	for _, object := range os.dnmap {
		if evaluate(object) {
			result.Add(object)
		}
	}
	return &result
}

func (os *Objects) Add(o *Object) {
	if o.ID == 0 {
		os.idcounter++
		o.ID = os.idcounter
	}

	os.asarray = append(os.asarray, o)
	os.objectmap[o] = struct{}{}
	os.dnmap[strings.ToLower(o.DN())] = o
	if sidstring := o.OneAttr(ObjectSid); sidstring != "" {
		sid, _, err := ParseSID([]byte(sidstring))
		if err == nil {
			existing, dupe := os.sidmap[sid]
			if dupe {
				log.Warn().Msgf("Duplicate SID when trying to add %v, already exists as %v, skipping import", o.DN(), existing.DN())
			} else {
				// log.Print("Adding", sid)
				os.sidmap[sid] = o
			}
		}
	}
	if sidstring := o.OneAttr(SIDHistory); sidstring != "" {
		sid, _, err := ParseSID([]byte(sidstring))
		if err == nil {
			existing, dupe := os.sidmap[sid]
			if dupe {
				log.Warn().Msgf("Duplicate SID when trying to add SIDhistory %v, already exists as %v, skipping import", o.DN(), existing.DN())
			} else {
				log.Debug().Msgf("Object %v with SIDHistory added", o.DN())
				os.sidmap[sid] = o
			}
		}
	}
	if guidstring := o.OneAttr(ObjectGUID); guidstring != "" {
		var guid uuid.UUID
		copy(guid[:], guidstring)
		os.guidmap[guid] = o
	}

	// Attributes etc
	if len(o.Attr(SchemaIDGUID)) > 0 {
		ldn := o.OneAttr(LDAPDisplayName)
		if ldn != "" {
			os.classmap[strings.ToLower(ldn)] = o
		}
	}

	// Statistics
	os.typecount[o.Type()]++
}

func (os Objects) Statistics() [OBJECTTYPEMAX]int {
	return os.typecount
}

func (os Objects) AsArray() []*Object {
	return os.asarray
}

func (os *Objects) Contains(o *Object) (found bool) {
	_, found = os.objectmap[o]
	return
}

func (os *Objects) Find(dn string) (o *Object, found bool) {
	o, found = os.dnmap[strings.ToLower(dn)]
	return
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
	return os.Find(dn)
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

func (os *Objects) FindSID(s SID) (o *Object, found bool) {
	o, found = os.sidmap[s]
	return
}

func (os *Objects) FindOne(a Attribute, value string) (*Object, error) {
	fo := os.Filter(func(o *Object) bool {
		return o.HasAttrValue(a, value)
	})
	foa := fo.AsArray()
	if len(foa) != 1 {
		return nil, errors.New("None or multiple objects found")
	}
	return foa[0], nil
}

func (os *Objects) FindOrAddSID(s SID) *Object {
	o, found := os.FindSID(s)
	if found {
		return o
	}
	u, _ := uuid.NewV4()
	o = &Object{
		DistinguishedName: "CN=" + s.String() + ",CN=synthetic",
		Attributes: map[Attribute][]string{
			Name:       {s.String()},
			ObjectGUID: {string(u.Bytes())},
			ObjectSid:  {string(s)},
		},
		CanPwn:    make(PwnConnections),
		PwnableBy: make(PwnConnections),
	}
	log.Info().Msgf("Adding unknown SID %v as %v", s, o.DistinguishedName)
	os.Add(o)
	return o
}

func (os *Objects) FindGUID(g uuid.UUID) (o *Object, found bool) {
	o, found = os.guidmap[g]
	return
}

func (os *Objects) FindClass(class string) (o *Object, found bool) {
	o, found = os.classmap[strings.ToLower(class)]
	return
}
