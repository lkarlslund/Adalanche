package engine

// ACEOrigin finds where the ACE at index in the node's DACL was set: the
// node itself for an explicit ACE, or for an inherited one the nearest
// ancestor holding a matching inheritable ACE that is explicit. Nil when that
// cannot be told, such as when an ancestor's security descriptor is missing.
func (o *Node) ACEOrigin(index int) *Node {
	sd, err := o.SecurityDescriptor()
	if err != nil || index < 0 || index >= len(sd.DACL.Entries) {
		return nil
	}
	ace := sd.DACL.Entries[index]
	if ace.ACEFlags&ACEFLAG_INHERITED_ACE == 0 {
		return o
	}
	for parent := o.Parent(); parent != nil; parent = parent.Parent() {
		psd, err := parent.SecurityDescriptor()
		if err != nil {
			return nil
		}
		var found, explicit bool
		for _, candidate := range psd.DACL.Entries {
			if candidate.SID == ace.SID && candidate.Type == ace.Type &&
				candidate.ObjectType == ace.ObjectType && candidate.InheritedObjectType == ace.InheritedObjectType &&
				candidate.ACEFlags&(ACEFLAG_OBJECT_INHERIT_ACE|ACEFLAG_INHERIT_ACE) != 0 {
				found = true
				if candidate.ACEFlags&ACEFLAG_INHERITED_ACE == 0 {
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
