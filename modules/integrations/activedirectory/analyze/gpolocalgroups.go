package analyze

import (
	"regexp"
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

var (
	// GPOLocalGroupMember holds "<local group SID>|<member name>|<setting>"
	// for computer-side GPO memberships that name the member instead of
	// giving its SID. The name can contain preference variables.
	GPOLocalGroupMember = engine.NewAttribute("gpoLocalGroupMember")
	// GPOLocalGroupMemberSID holds "<local group SID>|<member SID>|<setting>"
	// for computer-side GPO memberships given by SID.
	GPOLocalGroupMemberSID = engine.NewAttribute("gpoLocalGroupMemberSID")

	// GPOUserLocalGroupMember holds the same for user-side preference items.
	// These apply on the computers in-scope users log on to, so they are kept
	// for reference and not turned into edges.
	GPOUserLocalGroupMember = engine.NewAttribute("gpoUserLocalGroupMember")

	preferenceVariable = regexp.MustCompile(`(?i)%([a-z]+)%`)
	// %<Name>% marks a variable the editor chose not to resolve; the client
	// receives the literal %Name% (Variables in Preference Items).
	unresolvedVariable = regexp.MustCompile(`(?i)%<([a-z]+)>%`)
)

// Settings that make local group members, as named in edge causes.
const (
	gpoRestrictedGroups = "Restricted Groups"
	gpoGroupPreference  = "Local Users and Groups preference"
)

// localGroupName names the built-in local groups localGroupEdge knows.
func localGroupName(groupSID string) string {
	switch groupSID {
	case "S-1-5-32-544":
		return "Administrators"
	case "S-1-5-32-562":
		return "Distributed COM Users"
	case "S-1-5-32-555":
		return "Remote Desktop Users"
	}
	return groupSID
}

// gpoGrant is one local group membership a GPO setting gives.
type gpoGrant struct {
	groupSID, member, setting string
}

func parseGPOGrant(v string) gpoGrant {
	groupSID, rest, _ := strings.Cut(v, "|")
	member, setting, _ := strings.Cut(rest, "|")
	return gpoGrant{groupSID, member, setting}
}

func (g gpoGrant) value() string {
	return g.groupSID + "|" + g.member + "|" + g.setting
}

// cause is the edge cause for the grant made by gpo.
func (g gpoGrant) cause(gpo engine.NodeRef) engine.Source {
	setting := g.setting
	if setting == "" {
		setting = "Group Policy"
	}
	return engine.Source{Kind: SourceGPO, About: gpo, Detail: setting + ": member of " + localGroupName(g.groupSID)}
}

// localGroupEdge maps a built-in local group to the right membership grants.
func localGroupEdge(groupSID string) (engine.Edge, bool) {
	switch groupSID {
	case "S-1-5-32-544":
		return activedirectory.EdgeLocalAdminRights, true
	case "S-1-5-32-562":
		return activedirectory.EdgeLocalDCOMRights, true
	case "S-1-5-32-555":
		return activedirectory.EdgeLocalRDPRights, true
	}
	return engine.NonExistingEdge, false
}

// expandComputerVariables replaces the preference process variables that are
// fixed for a computer when its policy is processed: %ComputerName% (NetBIOS
// name) and %DomainName% (the computer's domain). Variables are not case
// sensitive. It reports false if any other variable remains, since those
// describe the logged-on user, the time or the local file system, and cannot
// be known from the directory.
func expandComputerVariables(name, computerName, domainName string) (string, bool) {
	ok := true
	expanded := preferenceVariable.ReplaceAllStringFunc(name, func(v string) string {
		switch strings.ToLower(preferenceVariable.FindStringSubmatch(v)[1]) {
		case "computername":
			return computerName
		case "domainname":
			if domainName != "" {
				return domainName
			}
		}
		ok = false
		return v
	})
	return expanded, ok
}

// gpoNameResolver finds the principal a GPO names, the way the client would
// when it looks the name up in its own domain.
type gpoNameResolver struct {
	ao        engine.GraphReader
	wellKnown map[string]windowssecurity.SID
}

func newGPONameResolver(ao engine.GraphReader) *gpoNameResolver {
	r := &gpoNameResolver{ao: ao, wellKnown: map[string]windowssecurity.SID{}}
	for sid, name := range windowssecurity.KnownSIDs {
		if parsed, err := windowssecurity.ParseStringSID(sid); err == nil {
			r.wellKnown[strings.ToLower(name)] = parsed
		}
	}
	return r
}

func (r *gpoNameResolver) unique(nodes engine.NodeSlice, found bool) *engine.Node {
	return r.uniqueIn(nodes, found, "")
}

// uniqueIn returns the only node, or the only one in domainContext.
func (r *gpoNameResolver) uniqueIn(nodes engine.NodeSlice, found bool, domainContext string) *engine.Node {
	if !found || nodes.Len() == 0 {
		return nil
	}
	if nodes.Len() == 1 {
		return nodes.First()
	}
	var match *engine.Node
	matches := 0
	nodes.Iterate(func(n *engine.Node) bool {
		if domainContext != "" && strings.EqualFold(n.OneAttrString(engine.DomainContext), domainContext) {
			match = n
			matches++
		}
		return true
	})
	if matches == 1 {
		return match
	}
	return nil
}

// resolve looks a name up as DOMAIN\name, name@domain or a bare account
// name. Bare names are tried in the given NetBIOS domain first.
func (r *gpoNameResolver) resolve(name, netbiosDomain, domainContext string) *engine.Node {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if domain, account, qualified := strings.Cut(name, "\\"); qualified {
		if n := r.unique(r.ao.FindMulti(engine.DownLevelLogonName, engine.NV(name))); n != nil {
			return n
		}
		switch strings.ToUpper(domain) {
		case "BUILTIN", "NT AUTHORITY", "NT-AUTORITÄT", "AUTORITE NT":
			return r.wellKnownNode(account)
		}
		return nil
	}
	if strings.Contains(name, "@") {
		return r.unique(r.ao.FindMulti(engine.UserPrincipalName, engine.NV(name)))
	}
	if netbiosDomain != "" {
		if n := r.unique(r.ao.FindMulti(engine.DownLevelLogonName, engine.NV(netbiosDomain+"\\"+name))); n != nil {
			return n
		}
	}
	nodes, found := r.ao.FindMulti(engine.SAMAccountName, engine.NV(name))
	if n := r.uniqueIn(nodes, found, domainContext); n != nil {
		return n
	}
	return r.wellKnownNode(name)
}

func (r *gpoNameResolver) wellKnownNode(name string) *engine.Node {
	sid, found := r.wellKnown[strings.ToLower(name)]
	if !found {
		if translated, err := TranslateLocalizedNameToSID(name); err == nil {
			sid, found = translated, true
		}
	}
	if !found {
		return nil
	}
	n, _ := r.ao.Find(engine.ObjectSid, engine.NV(sid))
	return n
}

// computerNames returns the values %ComputerName% and %DomainName% take on
// the machine, from its computer account.
func computerNames(ao engine.GraphReader, machine *engine.Node) (computerName, domainName, domainContext string, ok bool) {
	sid := machine.OneAttr(DomainJoinedSID)
	if sid.IsNil() {
		return "", "", "", false
	}
	computers, found := ao.FindMulti(engine.ObjectSid, sid)
	if !found {
		return "", "", "", false
	}
	var computer *engine.Node
	computers.Iterate(func(n *engine.Node) bool {
		if n.Type() == engine.NodeTypeComputer {
			computer = n
			return false
		}
		return true
	})
	if computer == nil {
		return "", "", "", false
	}
	computerName = strings.TrimSuffix(computer.OneAttrString(engine.SAMAccountName), "$")
	domainName, _, _ = strings.Cut(computer.OneAttrString(engine.DownLevelLogonName), "\\")
	return computerName, domainName, computer.OneAttrString(engine.DomainContext), computerName != ""
}

// gpoNetbiosDomain finds the NetBIOS name of the domain a GPO lives in, used
// for bare member names.
func gpoNetbiosDomain(ao engine.GraphReader, gpo *engine.Node) string {
	domainContext := gpo.OneAttrString(engine.DomainContext)
	if domainContext == "" {
		return ""
	}
	var netbios string
	crossrefs, _ := ao.FindMulti(engine.ObjectClass, engine.NV("crossRef"))
	crossrefs.Iterate(func(o *engine.Node) bool {
		if strings.EqualFold(o.OneAttrString(NCName), domainContext) {
			netbios = o.OneAttrString(NetBIOSName)
			return false
		}
		return true
	})
	return netbios
}

// resolveGPOLocalGroupMembers turns computer-side GPO local group
// memberships into rights on the machines the GPO applies to, each recording
// the GPO and setting as its cause. Members are given by SID, by plain name,
// or by a name with preference variables, which is expanded for each
// machine. A GPO that applies to no machine keeps its grants as attributes.
func resolveGPOLocalGroupMembers(tx *engine.Tx) {
	resolver := newGPONameResolver(tx)
	var bySID, resolved, perMachine, unresolved, unsupported int

	// Collect first: resolving adds nodes and edges, which cannot happen
	// while the graph is being iterated.
	var gpos []*engine.Node
	tx.Iterate(func(o *engine.Node) bool {
		if o.HasAttr(GPOLocalGroupMember) || o.HasAttr(GPOLocalGroupMemberSID) {
			gpos = append(gpos, o)
		}
		return true
	})

	for _, gpo := range gpos {
		var machines []*engine.Node
		tx.Edges(gpo, engine.Out).Iterate(func(target *engine.Node, eb engine.EdgeBitmap) bool {
			if eb.IsSet(activedirectory.EdgeAffectedByGPO) {
				machines = append(machines, target)
			}
			return true
		})
		if len(machines) == 0 {
			continue
		}
		grant := func(member engine.NodeRef, machine *engine.Node, edge engine.Edge, g gpoGrant) {
			tx.EdgeBecause(member, machine, edge, g.cause(gpo))
		}

		gpo.Attr(GPOLocalGroupMemberSID).Iterate(func(v engine.AttributeValue) bool {
			g := parseGPOGrant(v.String())
			edge, known := localGroupEdge(g.groupSID)
			sid, err := windowssecurity.ParseStringSID(g.member)
			if !known || err != nil {
				return true
			}
			member := tx.FindOrAddAdjacentSID(sid, gpo)
			for _, machine := range machines {
				grant(member, machine, edge, g)
			}
			bySID++
			return true
		})

		netbios := gpoNetbiosDomain(tx, gpo)
		domainContext := gpo.OneAttrString(engine.DomainContext)
		gpo.Attr(GPOLocalGroupMember).Iterate(func(v engine.AttributeValue) bool {
			g := parseGPOGrant(v.String())
			edge, known := localGroupEdge(g.groupSID)
			if !known {
				return true
			}
			name := g.member
			literal := unresolvedVariable.ReplaceAllString(name, "%$1%")
			if literal != name || !preferenceVariable.MatchString(name) {
				var member engine.NodeRef
				if resolvedMember := resolver.resolve(literal, netbios, domainContext); resolvedMember != nil {
					member = resolvedMember
					resolved++
				} else {
					// Keep the grant visible even when the name is unknown.
					member, _ = tx.FindOrAdd(engine.SAMAccountName, engine.NV(literal),
						engine.Name, engine.NV(literal),
						engine.DataLoader, engine.NV("Autogenerated"),
					)
					unresolved++
				}
				for _, machine := range machines {
					grant(member, machine, edge, g)
				}
				return true
			}

			for _, machine := range machines {
				computerName, domainName, machineContext, ok := computerNames(tx, machine)
				if !ok {
					unresolved++
					continue
				}
				expanded, ok := expandComputerVariables(name, computerName, domainName)
				if !ok {
					unsupported++
					continue
				}
				if member := resolver.resolve(expanded, domainName, machineContext); member != nil {
					grant(member, machine, edge, g)
					perMachine++
				} else {
					unresolved++
				}
			}
			return true
		})
	}

	if bySID+resolved+perMachine+unresolved+unsupported > 0 {
		ui.Info().Msgf("GPO local group members: %v given by SID, %v names resolved, %v resolved per machine from variables, %v not found, %v using variables that depend on the logged-on user or client", bySID, resolved, perMachine, unresolved, unsupported)
	}
}
