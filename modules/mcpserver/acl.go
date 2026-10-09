package mcpserver

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultACEs = 50
	maxACEs     = 500
)

func (s *Server) addACLTools() {
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name: "get_acl",
		Description: "Show a node's security descriptor in plain terms: owner, and each ACE with its trustee, the rights it grants or denies, " +
			"the property, extended right or class it is limited to, what it applies to, where an inherited ACE was set, and the edges it causes. " +
			"Edge causes such as \"ACE 45, inherited\" give the index to pass as ace; causes such as \"msDS-GroupMSAMembership ACE 3\" also name the attribute.",
	}, s.getACL)
}

type aclInput struct {
	NodeRef
	Attribute string `json:"attribute,omitempty" jsonschema:"the attribute holding the security descriptor, such as msDS-GroupMSAMembership; the object's own descriptor when left out"`
	ACE       *int   `json:"ace,omitempty" jsonschema:"only the ACE at this index"`
	Trustee   string `json:"trustee,omitempty" jsonschema:"only ACEs for this SID"`
	Skip      int    `json:"skip,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

// Trustee is the principal an ACE or the owner names.
type Trustee struct {
	SID  string     `json:"sid"`
	Name string     `json:"name,omitempty" jsonschema:"the well-known name of the SID, when it has one"`
	Node *NodeBrief `json:"node,omitempty" jsonschema:"the principal's node, as seen from this object's domain or machine"`
}

// SchemaRef is a GUID an ACE names, with what it is in the schema.
type SchemaRef struct {
	GUID string `json:"guid"`
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty" jsonschema:"extended right, validated write, property set, property or class"`
}

// ACEEdge is an edge an ACE causes, into the node.
type ACEEdge struct {
	From      NodeBrief `json:"from"`
	EdgeTypes []string  `json:"edge_types"`
}

// ACEView is one ACE of a DACL.
type ACEView struct {
	Index      int        `json:"index" jsonschema:"position in the DACL as edge causes give it: explicit denies, explicit allows, inherited denies, inherited allows"`
	Summary    string     `json:"summary"`
	Access     string     `json:"access" jsonschema:"allow or deny"`
	Trustee    Trustee    `json:"trustee"`
	Rights     []string   `json:"rights"`
	Mask       string     `json:"mask"`
	ObjectType *SchemaRef `json:"object_type,omitempty" jsonschema:"the property, property set, extended right, validated write or child class the rights are limited to"`
	AppliesTo  *SchemaRef `json:"applies_to,omitempty" jsonschema:"the class of descendants the ACE is inherited by"`
	Scope      string     `json:"scope" jsonschema:"what the ACE applies to: this object, its descendants, or both"`
	Inherited  bool       `json:"inherited"`
	SetOn      *NodeBrief `json:"set_on,omitempty" jsonschema:"where the ACE was set: this node, or for an inherited ACE the ancestor it came from"`
	Edges      []ACEEdge  `json:"edges,omitempty" jsonschema:"edges into this node that the ACE causes"`
}

type aclOutput struct {
	Meta      Meta      `json:"meta"`
	Node      NodeBrief `json:"node"`
	Attribute string    `json:"attribute"`
	Owner     *Trustee  `json:"owner,omitempty"`
	Group     *Trustee  `json:"group,omitempty"`
	// Protected is set when the DACL does not inherit from the parent.
	Protected bool      `json:"protected" jsonschema:"the DACL does not inherit ACEs from its parent"`
	Total     int       `json:"total" jsonschema:"ACEs matching the filters"`
	ACEs      []ACEView `json:"aces"`
}

func (s *Server) getACL(ctx context.Context, _ *mcp.CallToolRequest, in aclInput) (*mcp.CallToolResult, aclOutput, error) {
	g, err := s.Graph()
	if err != nil {
		return nil, aclOutput{}, err
	}
	node, err := s.Lookup(g, in.NodeRef)
	if err != nil {
		return nil, aclOutput{}, err
	}
	sd, attrName, err := descriptorOf(node, in.Attribute)
	if err != nil {
		return nil, aclOutput{}, err
	}
	var trustee windowssecurity.SID
	if in.Trustee != "" {
		if trustee, err = windowssecurity.ParseStringSID(strings.TrimSpace(in.Trustee)); err != nil {
			return nil, aclOutput{}, fmt.Errorf("trustee %q is not a SID: %v", in.Trustee, err)
		}
	}

	out := aclOutput{
		Meta:      s.Meta(),
		Node:      s.Brief(node),
		Attribute: attrName,
		Protected: sd.Control&engine.CONTROLFLAG_DACL_PROTECTED != 0,
	}
	if !sd.Owner.IsNull() {
		owner := s.trustee(g, sd.Owner, node)
		out.Owner = &owner
	}
	if !sd.Group.IsNull() {
		group := s.trustee(g, sd.Group, node)
		out.Group = &group
	}

	var selected []int
	for index, ace := range sd.DACL.Entries {
		if in.ACE != nil && *in.ACE != index {
			continue
		}
		if in.Trustee != "" && ace.SID != trustee {
			continue
		}
		selected = append(selected, index)
	}
	if in.ACE != nil && len(selected) == 0 {
		return nil, aclOutput{}, fmt.Errorf("the DACL has no ACE %d (it has %d)", *in.ACE, len(sd.DACL.Entries))
	}
	out.Total = len(selected)
	skip := min(max(in.Skip, 0), len(selected))
	end := min(skip+clampLimit(in.Limit, defaultACEs, maxACEs), len(selected))
	selected = selected[skip:end]

	edges := s.aceEdges(ctx, g, node, attrName)
	if err := ctx.Err(); err != nil {
		return nil, aclOutput{}, err
	}
	rights := rightsFor(node)
	for _, index := range selected {
		ace := sd.DACL.Entries[index]
		view := ACEView{
			Index:     index,
			Access:    "allow",
			Trustee:   s.trustee(g, ace.SID, node),
			Rights:    rights(ace.Mask),
			Mask:      fmt.Sprintf("0x%08x", uint32(ace.Mask)),
			Scope:     aceScope(ace),
			Inherited: ace.ACEFlags&engine.ACEFLAG_INHERITED_ACE != 0,
			Edges:     edges[index],
		}
		if ace.Type == engine.ACETYPE_ACCESS_DENIED || ace.Type == engine.ACETYPE_ACCESS_DENIED_OBJECT {
			view.Access = "deny"
		}
		if ace.Flags&engine.OBJECT_TYPE_PRESENT != 0 {
			view.ObjectType = schemaRef(g, ace.ObjectType, ace.Mask)
		}
		if ace.Flags&engine.INHERITED_OBJECT_TYPE_PRESENT != 0 {
			view.AppliesTo = schemaRef(g, ace.InheritedObjectType, 0)
		}
		if attrName == engine.NTSecurityDescriptor.String() {
			view.SetOn = s.briefOf(node.ACEOrigin(index))
		}
		view.Summary = aceSummary(view)
		out.ACEs = append(out.ACEs, view)
	}
	return nil, out, nil
}

// descriptorOf returns the security descriptor held in the attribute, or the
// node's own when attr is blank.
func descriptorOf(node *engine.Node, attr string) (*engine.SecurityDescriptor, string, error) {
	if attr == "" || strings.EqualFold(attr, engine.NTSecurityDescriptor.String()) {
		sd, err := node.SecurityDescriptor()
		if err != nil {
			return nil, "", fmt.Errorf("%s has no security descriptor", node.Label())
		}
		return sd, engine.NTSecurityDescriptor.String(), nil
	}
	a := engine.LookupAttribute(attr)
	if a == engine.NonExistingAttribute {
		return nil, "", fmt.Errorf("no attribute %q", attr)
	}
	for _, value := range node.Attr(a) {
		if sd, ok := value.AsSecurityDescriptor(); ok && sd != nil {
			return sd, a.String(), nil
		}
	}
	return nil, "", fmt.Errorf("%s holds no security descriptor in %s", node.Label(), a.String())
}

func (s *Server) trustee(g *engine.IndexedGraph, sid windowssecurity.SID, relativeTo *engine.Node) Trustee {
	t := Trustee{SID: sid.String(), Name: windowssecurity.KnownSIDs[sid.String()]}
	if principal, found := g.FindAdjacentSID(sid, relativeTo); found {
		t.Node = s.briefOf(principal)
	}
	return t
}

// schemaRef names a GUID from an ACE by the schema objects and extended
// rights in the graph. The mask tells an extended right from a validated
// write or a property set, which share the controlAccessRight class.
func schemaRef(g *engine.IndexedGraph, guid uuid.UUID, mask engine.Mask) *SchemaRef {
	ref := &SchemaRef{GUID: guid.String()}
	if right, found := firstNode(g, engine.RightsGUID, guid); found {
		ref.Name = schemaName(right)
		switch {
		case mask&engine.RIGHT_DS_CONTROL_ACCESS != 0:
			ref.Kind = "extended right"
		case mask&engine.RIGHT_DS_WRITE_PROPERTY_EXTENDED != 0:
			ref.Kind = "validated write"
		case mask&(engine.RIGHT_DS_READ_PROPERTY|engine.RIGHT_DS_WRITE_PROPERTY) != 0:
			ref.Kind = "property set"
		default:
			ref.Kind = "extended right"
		}
		return ref
	}
	if schema, found := firstNode(g, engine.SchemaIDGUID, guid); found {
		ref.Name = schemaName(schema)
		ref.Kind = "property"
		for _, class := range schema.Attr(engine.ObjectClass) {
			if strings.EqualFold(class.String(), "classSchema") {
				ref.Kind = "class"
			}
		}
	}
	return ref
}

// firstNode finds a node by a GUID attribute. Each forest has its own schema,
// so several nodes can carry one GUID; they share the name.
func firstNode(g *engine.IndexedGraph, attr engine.Attribute, guid uuid.UUID) (*engine.Node, bool) {
	nodes, found := g.FindMulti(attr, engine.NV(guid))
	if !found || nodes.Len() == 0 {
		return nil, false
	}
	return nodes.First(), true
}

func schemaName(n *engine.Node) string {
	for _, attr := range []engine.Attribute{engine.LDAPDisplayName, engine.DisplayName, engine.Name} {
		if name := n.OneAttrString(attr); name != "" {
			return name
		}
	}
	return n.Label()
}

// aceScope says what an ACE applies to, from its inheritance flags.
func aceScope(ace engine.ACE) string {
	var parts []string
	if ace.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE == 0 {
		parts = append(parts, "this object")
	}
	children := "descendants"
	if ace.ACEFlags&engine.ACEFLAG_NO_PROPAGATE_INHERIT_ACE != 0 {
		children = "direct children"
	}
	switch ace.ACEFlags & (engine.ACEFLAG_INHERIT_ACE | engine.ACEFLAG_OBJECT_INHERIT_ACE) {
	case engine.ACEFLAG_INHERIT_ACE | engine.ACEFLAG_OBJECT_INHERIT_ACE:
		parts = append(parts, children)
	case engine.ACEFLAG_INHERIT_ACE:
		parts = append(parts, "container "+children)
	case engine.ACEFLAG_OBJECT_INHERIT_ACE:
		parts = append(parts, "non-container "+children)
	}
	if len(parts) == 0 {
		return "nothing (inherit-only without inheritance)"
	}
	return strings.Join(parts, " and ")
}

func aceSummary(v ACEView) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ACE %d: %s %s", v.Index, strings.ToUpper(v.Access[:1])+v.Access[1:], trusteeName(v.Trustee))
	fmt.Fprintf(&b, " %s", strings.Join(v.Rights, ", "))
	if v.ObjectType != nil {
		name := v.ObjectType.Name
		if name == "" {
			name = v.ObjectType.GUID
		}
		if v.ObjectType.Kind != "" {
			fmt.Fprintf(&b, " limited to %s %s", v.ObjectType.Kind, name)
		} else {
			fmt.Fprintf(&b, " limited to %s", name)
		}
	}
	fmt.Fprintf(&b, ", on %s", v.Scope)
	if v.AppliesTo != nil {
		name := v.AppliesTo.Name
		if name == "" {
			name = v.AppliesTo.GUID
		}
		fmt.Fprintf(&b, " of class %s", name)
	}
	if v.Inherited {
		if v.SetOn != nil {
			fmt.Fprintf(&b, "; inherited from %s", v.SetOn.Label)
		} else {
			b.WriteString("; inherited")
		}
	}
	return b.String()
}

func trusteeName(t Trustee) string {
	switch {
	case t.Node != nil:
		return t.Node.Label
	case t.Name != "":
		return t.Name
	}
	return t.SID
}

// Generic rights as stored in a mask, before mapping to specific rights.
const (
	genericAll     engine.Mask = 0x10000000
	genericExecute engine.Mask = 0x20000000
	genericWrite   engine.Mask = 0x40000000
	genericRead    engine.Mask = 0x80000000
)

type rightName struct {
	mask engine.Mask
	name string
}

var standardRights = []rightName{
	{engine.RIGHT_DELETE, "Delete"},
	{engine.RIGHT_READ_CONTROL, "ReadControl"},
	{engine.RIGHT_WRITE_DACL, "WriteDacl"},
	{engine.RIGHT_WRITE_OWNER, "WriteOwner"},
	{engine.RIGHT_SYNCRONIZE, "Synchronize"},
	{engine.RIGHT_ACCESS_SYSTEM_SECURITY, "AccessSystemSecurity"},
	{engine.RIGHT_MAXIMUM_ALLOWED, "MaximumAllowed"},
	{genericAll, "GenericAll"},
	{genericExecute, "GenericExecute"},
	{genericWrite, "GenericWrite"},
	{genericRead, "GenericRead"},
}

var directoryRights = []rightName{
	{engine.RIGHT_DS_CREATE_CHILD, "CreateChild"},
	{engine.RIGHT_DS_DELETE_CHILD, "DeleteChild"},
	{engine.RIGHT_DS_LIST_CONTENTS, "ListChildren"},
	{engine.RIGHT_DS_WRITE_PROPERTY_EXTENDED, "Self (validated write)"},
	{engine.RIGHT_DS_READ_PROPERTY, "ReadProperty"},
	{engine.RIGHT_DS_WRITE_PROPERTY, "WriteProperty"},
	{engine.RIGHT_DS_DELETE_TREE, "DeleteTree"},
	{engine.RIGHT_DS_LIST_OBJECT, "ListObject"},
	{engine.RIGHT_DS_CONTROL_ACCESS, "ControlAccess (extended rights)"},
}

var fileRights = []rightName{
	{engine.FILE_READ_DATA, "ReadData/ListDirectory"},
	{engine.FILE_WRITE_DATA, "WriteData/AddFile"},
	{engine.FILE_APPEND_DATA, "AppendData/AddSubdirectory"},
	{engine.FILE_READ_EA, "ReadExtendedAttributes"},
	{engine.FILE_WRITE_EA, "WriteExtendedAttributes"},
	{engine.FILE_EXECUTE, "Execute/Traverse"},
	{engine.FILE_DELETE_CHILD, "DeleteChild"},
	{engine.FILE_READ_ATTRIBUTES, "ReadAttributes"},
	{engine.FILE_WRITE_ATTRIBUTES, "WriteAttributes"},
}

const (
	directoryFullControl engine.Mask = 0x000f01ff
	fileFullControl      engine.Mask = 0x001f01ff
)

// rightsFor returns how to name the rights in a mask for the node's kind of
// object: files and shares use file rights, other objects with a
// distinguished name directory rights, and anything else only the standard
// rights and the mask.
func rightsFor(node *engine.Node) func(engine.Mask) []string {
	var specific []rightName
	var full engine.Mask
	switch node.Type().Lookup() {
	case engine.NodeTypeFile.Lookup(), engine.NodeTypeDirectory.Lookup(), engine.NodeTypeExecutable.Lookup(), "Share":
		specific, full = fileRights, fileFullControl
	default:
		if node.DN() != "" {
			specific, full = directoryRights, directoryFullControl
		}
	}
	return func(mask engine.Mask) []string {
		var names []string
		if full != 0 && mask&full == full {
			names = append(names, "FullControl")
			mask &^= full
		}
		for _, r := range specific {
			if mask&r.mask != 0 {
				names = append(names, r.name)
				mask &^= r.mask
			}
		}
		for _, r := range standardRights {
			if mask&r.mask != 0 {
				names = append(names, r.name)
				mask &^= r.mask
			}
		}
		if mask != 0 {
			names = append(names, fmt.Sprintf("0x%x", uint32(mask)))
		}
		return names
	}
}

// aceCause reads the ACE index from an edge cause detail, such as "ACE 45",
// "ACE 45, inherited", "file ACE 3" or "msDS-GroupMSAMembership ACE 3".
var aceCause = regexp.MustCompile(`^(?:(\S+) )?ACE (\d+)(?:,|$)`)

// causeACE returns the descriptor attribute and ACE index an edge cause
// names, if it names one.
func causeACE(detail string) (string, int, bool) {
	m := aceCause.FindStringSubmatch(detail)
	if m == nil {
		return "", 0, false
	}
	index, err := strconv.Atoi(m[2])
	if err != nil {
		return "", 0, false
	}
	attr := m[1]
	if attr == "" || attr == "file" {
		attr = engine.NTSecurityDescriptor.String()
	}
	return attr, index, true
}

// aceEdges finds the edges into node caused by ACEs of the descriptor in
// attr, by ACE index.
func (s *Server) aceEdges(ctx context.Context, g *engine.IndexedGraph, node *engine.Node, attr string) map[int][]ACEEdge {
	result := map[int][]ACEEdge{}
	var seen int
	g.IterateEdges(node, engine.In, func(from *engine.Node, _ engine.EdgeBitmap) bool {
		byIndex := map[int][]string{}
		for _, p := range g.EdgeSources(from, node) {
			causeAttr, index, ok := causeACE(p.Source.Detail)
			if !ok || !strings.EqualFold(causeAttr, attr) {
				continue
			}
			byIndex[index] = append(byIndex[index], p.Edge.String())
		}
		for index, types := range byIndex {
			result[index] = append(result[index], ACEEdge{From: s.Brief(from), EdgeTypes: types})
		}
		seen++
		return !cancelled(ctx, seen)
	})
	return result
}
