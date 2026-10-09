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

	// SourceAttribute is the cause of edges read from a directory
	// attribute; the source is about the object holding it, and the
	// detail names the attribute.
	SourceAttribute = engine.NewSourceKind("Directory attribute")

	// SourceInference is the cause of edges that follow from how Windows
	// and Active Directory work rather than from one piece of data, such as
	// every account being an Authenticated User; the detail says which.
	SourceInference = engine.NewSourceKind("Inference")
)

// DescriptorACECause is the cause of edges granted by an ACE in a security
// descriptor held in another attribute than nTSecurityDescriptor.
func DescriptorACECause(attr engine.Attribute, index int, ace engine.ACE) engine.Source {
	source := ACECause(index, ace)
	source.Detail = attr.String() + " " + source.Detail
	return source
}

// RightsCause is the cause of edges granted by rights the ACEs of about's
// security descriptor give together, such as reading a LAPS password.
func RightsCause(about engine.NodeRef, rights string) engine.Source {
	return engine.Source{Kind: SourceACL, About: about, Detail: rights}
}

// FileACECause is the cause of edges granted by an ACE in a file's DACL,
// the edge's target.
func FileACECause(index int, ace engine.ACE) engine.Source {
	source := ACECause(index, ace)
	source.Detail = "file " + source.Detail
	return source
}

// FileOwnerCause is the cause of an edge from a file's owner.
func FileOwnerCause() engine.Source {
	return engine.Source{Kind: SourceACL, Detail: "file owner"}
}

// OwnerCause is the cause of an edge from the owner in the target's
// security descriptor.
func OwnerCause() engine.Source {
	return engine.Source{Kind: SourceACL, Detail: "owner"}
}

// AttributeCause is the cause of an edge read from an attribute of about.
func AttributeCause(about engine.NodeRef, attr engine.Attribute) engine.Source {
	return engine.Source{Kind: SourceAttribute, About: about, Detail: attr.String()}
}

// Inferred is the cause of an edge that follows from how Windows and Active
// Directory work; detail says which rule.
func Inferred(detail string) engine.Source {
	return engine.Source{Kind: SourceInference, Detail: detail}
}

// ACECause is the cause of edges granted by the ACE at index in the target's
// DACL.
func ACECause(index int, ace engine.ACE) engine.Source {
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
		// Not an ACE of the target's own descriptor: rights from several
		// ACEs, the owner, or another attribute's descriptor.
		if s.About != nil {
			return s.About
		}
		return target
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
