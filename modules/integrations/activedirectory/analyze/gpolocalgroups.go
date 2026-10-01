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
	// GPOLocalGroupMember holds "<local group SID>|<member name>" for
	// computer-side GPO memberships that name the member instead of giving
	// its SID. The name can contain preference variables.
	GPOLocalGroupMember = engine.NewAttribute("gpoLocalGroupMember")
	// GPOUserLocalGroupMember holds the same for user-side preference items.
	// These apply on the computers in-scope users log on to, so they are kept
	// for reference and not turned into edges.
	GPOUserLocalGroupMember = engine.NewAttribute("gpoUserLocalGroupMember")

	preferenceVariable = regexp.MustCompile(`(?i)%([a-z]+)%`)
	// %<Name>% marks a variable the editor chose not to resolve; the client
	// receives the literal %Name% (Variables in Preference Items).
	unresolvedVariable = regexp.MustCompile(`(?i)%<([a-z]+)>%`)
)

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
	ao        *engine.IndexedGraph
	wellKnown map[string]windowssecurity.SID
}

func newGPONameResolver(ao *engine.IndexedGraph) *gpoNameResolver {
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
func computerNames(ao *engine.IndexedGraph, machine *engine.Node) (computerName, domainName, domainContext string, ok bool) {
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
func gpoNetbiosDomain(ao *engine.IndexedGraph, gpo *engine.Node) string {
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

// resolveGPOLocalGroupMembers turns computer-side GPO memberships given by
// name into edges. Plain names become edges to the GPO, like members given by
// SID. Names with preference variables are expanded for each machine the GPO
// applies to, and the resolved principal gets the right on that machine.
func resolveGPOLocalGroupMembers(ao *engine.IndexedGraph) {
	resolver := newGPONameResolver(ao)
	var resolved, perMachine, unresolved, unsupported int

	// Collect first: resolving adds nodes and edges, which cannot happen
	// while the graph is being iterated.
	var gpos []*engine.Node
	ao.Iterate(func(o *engine.Node) bool {
		if o.HasAttr(GPOLocalGroupMember) {
			gpos = append(gpos, o)
		}
		return true
	})

	for _, gpo := range gpos {
		values := gpo.Attr(GPOLocalGroupMember)
		netbios := gpoNetbiosDomain(ao, gpo)
		domainContext := gpo.OneAttrString(engine.DomainContext)

		var machines []*engine.Node
		ao.Edges(gpo, engine.Out).Iterate(func(target *engine.Node, eb engine.EdgeBitmap) bool {
			if eb.IsSet(activedirectory.EdgeAffectedByGPO) {
				machines = append(machines, target)
			}
			return true
		})

		values.Iterate(func(v engine.AttributeValue) bool {
			groupSID, name, _ := strings.Cut(v.String(), "|")
			literal := unresolvedVariable.ReplaceAllString(name, "%$1%")
			edge, known := localGroupEdge(groupSID)
			if !known {
				return true
			}

			if literal != name || !preferenceVariable.MatchString(name) {
				name = literal
				member := resolver.resolve(name, netbios, domainContext)
				if member == nil {
					// Keep the grant visible even when the name is unknown.
					member, _ = ao.FindOrAdd(engine.SAMAccountName, engine.NV(name),
						engine.Name, engine.NV(name),
						engine.DataLoader, engine.NV("Autogenerated"),
					)
					unresolved++
				} else {
					resolved++
				}
				ao.EdgeTo(member, gpo, edge)
				return true
			}

			for _, machine := range machines {
				computerName, domainName, machineContext, ok := computerNames(ao, machine)
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
					ao.EdgeTo(member, machine, edge)
					perMachine++
				} else {
					unresolved++
				}
			}
			return true
		})
	}

	if resolved+perMachine+unresolved+unsupported > 0 {
		ui.Info().Msgf("GPO local group members given by name: %v resolved, %v resolved per machine from variables, %v not found, %v using variables that depend on the logged-on user or client", resolved, perMachine, unresolved, unsupported)
	}
}
