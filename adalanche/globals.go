package main

import (
	"github.com/gofrs/uuid"
	"github.com/mattn/go-colorable"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Truly horrible, shoot me already

var (
	randguid, _    = uuid.NewV4()
	AttackerSID, _ = SIDFromString("S-1-555-1337")
	AttackerObject = &Object{
		DistinguishedName: "CN=Attacker",
		Attributes: map[Attribute]AttributeValues{
			Name:       {AttributeValueString("Attacker")},
			ObjectSid:  {AttributeValueSID(AttackerSID)},
			ObjectGUID: {AttributeValueGUID(randguid)},
		},
	}

	// HackersWonSID, _ = SIDFromString("S-1-555-13337")
	// randguid2, _     = uuid.NewV4()
	// HackersWonObject = &Object{
	// 	DistinguishedName: "CN=Hackers Won",
	// 	Attributes: map[Attribute][]string{
	// 		Name:       {"Hackers Won"},
	// 		ObjectSid:  {string(HackersWonSID)},
	// 		ObjectGUID: {string(randguid2.Bytes())},
	// 	},
	// }

	AllObjects              Objects
	SecurityDescriptorCache = make(map[uint32]*SecurityDescriptor)
	AllRights               = make(map[uuid.UUID]*Object) // Extented-Rights from Configuration - rightsGUID -> object
	AllSchemaClasses        = make(map[uuid.UUID]*Object) // schemaIdGUID -> object
	AllSchemaAttributes     = make(map[uuid.UUID]*Object) // attribute ...
)

func init() {
	AttackerObject.init()
	// HackersWonObject.init()

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: colorable.NewColorableStdout()})
	AllObjects.Init(nil)
	AllObjects.Add(AttackerObject)
	// AllObjects.Add(HackersWonObject)
}
