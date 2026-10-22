package analyze

import (
	"slices"
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"golang.org/x/text/encoding/unicode"
	"gopkg.in/ini.v1"
)

// User rights a GPO assigns (Security Settings, User Rights Assignment, the
// [Privilege Rights] section of GptTmpl.inf) become the same edges a
// machine's own collection gives (see activedirectory.PrivilegeEdge), on the
// machines the GPO applies to. Unlike most settings, a right's assignment is
// not added up across GPOs: the GPO the machine applies last that assigns
// the right decides who holds it, so the machines' order of applying GPOs is
// worked out first. A machine whose own collection lists its rights keeps
// those, as they are what it actually has.

var (
	// GPOUserRight holds "<right>|<members>" for each right a GPO assigns,
	// the members as GptTmpl.inf lists them: *SID or a name, comma separated,
	// empty when the GPO assigns the right to no one.
	GPOUserRight = engine.NewAttribute("gpoUserRight")
	// GPOApplicationOrder holds the distinguished names of the GPOs that
	// apply to a machine, in the order it applies them: where they disagree,
	// a later one wins.
	GPOApplicationOrder = engine.NewAttribute("gpoApplicationOrder")
)

// gpoUserRight is one right a GPO assigns, and to whom.
type gpoUserRight struct {
	right   string
	members []string // *SID or name
}

func (r gpoUserRight) value() string {
	return r.right + "|" + strings.Join(r.members, ",")
}

func parseGPOUserRight(v string) gpoUserRight {
	right, members, _ := strings.Cut(v, "|")
	r := gpoUserRight{right: right}
	for m := range strings.SplitSeq(members, ",") {
		if m = strings.TrimSpace(m); m != "" {
			r.members = append(r.members, m)
		}
	}
	return r
}

// GPOparsePrivilegeRights reads the user rights a GptTmpl.inf assigns.
func GPOparsePrivilegeRights(rawini string) []gpoUserRight {
	// GptTmpl.inf is UTF-16 with a byte order mark; anything else is read
	// as it is.
	text := []byte(rawini)
	if strings.HasPrefix(rawini, "\xff\xfe") || strings.HasPrefix(rawini, "\xfe\xff") {
		if decoded, err := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder().Bytes(text); err == nil {
			text = decoded
		}
	}
	gpt, err := ini.LoadSources(ini.LoadOptions{SkipUnrecognizableLines: true}, text)
	if err != nil {
		return nil
	}
	var rights []gpoUserRight
	for _, key := range gpt.Section("Privilege Rights").Keys() {
		rights = append(rights, parseGPOUserRight(key.Name()+"|"+key.String()))
	}
	return rights
}

// gpoLink is a GPO applying to a machine through one link: som counts the
// scopes of management from the machine up (0 is its own OU, the site
// last), link is the link's place in that scope's gPLink.
type gpoLink struct {
	gpo      *engine.Node
	som      int
	link     int
	enforced bool
}

// gpoApplicationOrder puts the GPOs in the order a machine applies them:
// site, domain, then OUs from the top down, and within a scope its gPLink in
// order, which lists the lowest precedence first. Enforced links follow all
// others, with the higher scopes last, so they win. A GPO linked twice
// applies where it comes last.
func gpoApplicationOrder(links []gpoLink) []*engine.Node {
	ordered := slices.Clone(links)
	slices.SortStableFunc(ordered, func(a, b gpoLink) int {
		switch {
		case a.enforced != b.enforced:
			if a.enforced {
				return 1
			}
			return -1
		case a.som != b.som:
			if a.enforced {
				return a.som - b.som // enforced: nearest first, top last
			}
			return b.som - a.som // not enforced: top first, nearest last
		}
		return a.link - b.link
	})
	var order []*engine.Node
	for i, l := range ordered {
		if !slices.ContainsFunc(ordered[i+1:], func(later gpoLink) bool { return later.gpo == l.gpo }) {
			order = append(order, l.gpo)
		}
	}
	return order
}

// resolveGPOUserRights gives each machine the rights the GPOs it applies
// assign, as edges from the members to the machine.
func resolveGPOUserRights(tx *engine.Tx) {
	resolver := newGPONameResolver(tx)
	type gpoInfo struct {
		node                   *engine.Node
		rights                 []gpoUserRight
		netbios, domainContext string
	}
	gpos := map[string]*gpoInfo{}
	gpoNamed := func(dn string) *gpoInfo {
		if info, found := gpos[dn]; found {
			return info
		}
		var info *gpoInfo
		if node, found := tx.Find(engine.DistinguishedName, engine.NV(dn)); found {
			info = &gpoInfo{node: node, domainContext: node.OneAttrString(engine.DomainContext)}
			node.Attr(GPOUserRight).Iterate(func(v engine.AttributeValue) bool {
				info.rights = append(info.rights, parseGPOUserRight(v.String()))
				return true
			})
			if len(info.rights) > 0 {
				info.netbios = gpoNetbiosDomain(tx, node)
			}
		}
		gpos[dn] = info
		return info
	}

	// Collect first: edges can not be added while the graph is iterated.
	var machines []*engine.Node
	tx.Iterate(func(o *engine.Node) bool {
		if o.Type() == ObjectTypeMachine && o.HasAttr(GPOApplicationOrder) && !o.HasAttr(localmachine.CollectedAt) {
			machines = append(machines, o)
		}
		return true
	})

	var edges, unresolved int
	for _, machine := range machines {
		type assignment struct {
			members []string
			gpo     *gpoInfo
		}
		effective := map[string]assignment{}
		machine.Attr(GPOApplicationOrder).Iterate(func(v engine.AttributeValue) bool {
			if info := gpoNamed(v.String()); info != nil {
				for _, r := range info.rights {
					effective[r.right] = assignment{r.members, info}
				}
			}
			return true
		})
		for right, a := range effective {
			edge, known := activedirectory.PrivilegeEdge(right)
			if !known {
				continue
			}
			denied := effective[activedirectory.DenyingRight(right)].members
			for _, member := range a.members {
				if slices.ContainsFunc(denied, func(d string) bool { return strings.EqualFold(d, member) }) {
					continue
				}
				var principal engine.NodeRef
				if sidtext, isSID := strings.CutPrefix(member, "*"); isSID {
					sid, err := windowssecurity.ParseStringSID(sidtext)
					if err != nil {
						unresolved++
						continue
					}
					principal = tx.FindOrAddAdjacentSID(sid, a.gpo.node)
				} else if node := resolver.resolve(member, a.gpo.netbios, a.gpo.domainContext); node != nil {
					principal = node
				} else {
					unresolved++
					continue
				}
				tx.EdgeBecause(principal, machine, edge, engine.Source{Kind: SourceGPO, About: a.gpo.node, Detail: "User Rights Assignment: " + right})
				edges++
			}
		}
	}
	if edges+unresolved > 0 {
		ui.Info().Msgf("GPO user rights: %v grants on %v machines, %v members not found", edges, len(machines), unresolved)
	}
}
