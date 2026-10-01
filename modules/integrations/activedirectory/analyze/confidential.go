package analyze

import (
	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// searchFlagConfidential is fCONFIDENTIAL in an attributeSchema's searchFlags.
const searchFlagConfidential = 0x80

// AttributeReadRights returns the rights needed to read the attribute with
// this schemaIDGUID. Confidential attributes need RIGHT_DS_CONTROL_ACCESS as
// well as RIGHT_DS_READ_PROPERTY (MS-ADTS 3.1.1.4.4). The schema decides when
// it was collected; otherwise confidentialByDefault does.
func AttributeReadRights(ao *engine.IndexedGraph, attribute uuid.UUID, confidentialByDefault bool) engine.Mask {
	confidential := confidentialByDefault
	if schema, found := ao.Find(activedirectory.SchemaIDGUID, engine.NV(attribute)); found {
		if flags, ok := schema.AttrInt(activedirectory.SearchFlags); ok {
			confidential = flags&searchFlagConfidential != 0
		}
	}
	if confidential {
		return engine.RIGHT_DS_READ_PROPERTY | engine.RIGHT_DS_CONTROL_ACCESS
	}
	return engine.RIGHT_DS_READ_PROPERTY
}

// PrincipalsGranted returns each trustee in the DACL that the descriptor
// grants all of mask for the object or attribute guid, counting rights spread
// over several of its ACEs and honouring its denies. Like the other ACL edges,
// it evaluates each trustee on its own, not a member's full token.
func PrincipalsGranted(sd *engine.SecurityDescriptor, o *engine.Node, mask engine.Mask, guid uuid.UUID, ao *engine.IndexedGraph) []windowssecurity.SID {
	var granted []windowssecurity.SID
	seen := map[windowssecurity.SID]struct{}{}
	for _, ace := range sd.DACL.Entries {
		if _, done := seen[ace.SID]; done {
			continue
		}
		seen[ace.SID] = struct{}{}
		sid := ace.SID
		if sd.AccessCheck(func(s windowssecurity.SID) bool { return s == sid }, o, mask, guid, ao) {
			granted = append(granted, sid)
		}
	}
	return granted
}
