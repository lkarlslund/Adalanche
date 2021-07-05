package main

import (
	"strings"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

type Objects struct {
	Base      string
	asarray   []*Object
	objectmap map[*Object]struct{}
	dnmap     map[string]*Object
	sidmap    map[SID]*Object
	guidmap   map[uuid.UUID]*Object
	typecount [OBJECTTYPEMAX]int
}

func (os *Objects) Init(base string) {
	os.Base = base
	os.objectmap = make(map[*Object]struct{})
	os.dnmap = make(map[string]*Object)
	os.sidmap = make(map[SID]*Object)
	os.guidmap = make(map[uuid.UUID]*Object)
}

func (os *Objects) Filter(evaluate func(o *Object) bool) *Objects {
	var result Objects
	result.Init(os.Base)

	for _, object := range os.dnmap {
		if evaluate(object) {
			result.Add(object)
		}
	}
	return &result
}

func (os *Objects) Add(o *Object) {
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
	}
	log.Info().Msgf("Adding unknown SID %v as %v", s, o.DistinguishedName)
	os.Add(o)
	return o
}

func (os *Objects) FindGUID(g uuid.UUID) (o *Object, found bool) {
	o, found = os.guidmap[g]
	return
}
