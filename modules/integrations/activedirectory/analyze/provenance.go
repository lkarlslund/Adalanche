package analyze

import (
	"fmt"

	"github.com/lkarlslund/adalanche/modules/engine"
)

var (
	// SourceGPO is the cause of edges a GPO setting grants; the source is
	// about the GPO, and the detail names the setting.
	SourceGPO = engine.NewSourceKind("Group Policy")

	// SourceACL is the cause of edges an ACE grants. It is about the edge's
	// target, whose security descriptor holds the ACE; the detail gives the
	// ACE's position and whether it was inherited, so where an inherited
	// ACE was set can be found by walking up from the target.
	SourceACL = engine.NewSourceKind("Security descriptor")
)

// aceCause is the cause of edges granted by the ACE at index in the target's
// DACL.
func aceCause(index int, ace engine.ACE) engine.Source {
	detail := fmt.Sprintf("ACE %d", index)
	if ace.ACEFlags&engine.ACEFLAG_INHERITED_ACE != 0 {
		detail += ", inherited"
	}
	return engine.Source{Kind: SourceACL, Detail: detail}
}

func init() {
	engine.RegisterSourceOrigin(SourceACL, aceOrigin)
}

// aceOrigin finds where the ACE behind an ACL cause was set: the edge's
// target for an explicit ACE, or for an inherited one the nearest ancestor
// whose matching inheritable ACE is explicit. Nil when that cannot be told.
func aceOrigin(_, target *engine.Node, s engine.EdgeSource) *engine.Node {
	var index int
	if _, err := fmt.Sscanf(s.Detail, "ACE %d", &index); err != nil {
		return nil
	}
	sd, err := target.SecurityDescriptor()
	if err != nil || index < 0 || index >= len(sd.DACL.Entries) {
		return nil
	}
	ace := sd.DACL.Entries[index]
	if ace.ACEFlags&engine.ACEFLAG_INHERITED_ACE == 0 {
		return target
	}
	for parent := target.Parent(); parent != nil; parent = parent.Parent() {
		psd, err := parent.SecurityDescriptor()
		if err != nil {
			return nil
		}
		var found, explicit bool
		for _, candidate := range psd.DACL.Entries {
			if candidate.SID == ace.SID && candidate.Type == ace.Type &&
				candidate.ObjectType == ace.ObjectType && candidate.InheritedObjectType == ace.InheritedObjectType &&
				candidate.ACEFlags&(engine.ACEFLAG_OBJECT_INHERIT_ACE|engine.ACEFLAG_INHERIT_ACE) != 0 {
				found = true
				if candidate.ACEFlags&engine.ACEFLAG_INHERITED_ACE == 0 {
					explicit = true
					break
				}
			}
		}
		if !found {
			return nil
		}
		if explicit {
			return parent
		}
	}
	return nil
}
