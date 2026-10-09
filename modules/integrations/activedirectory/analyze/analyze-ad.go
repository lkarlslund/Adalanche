package analyze

import (
	"encoding/binary"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/graph"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/integrations/attrs"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// Interesting permissions on AD
var (
	ResetPwd, _                             = uuid.FromString("{00299570-246d-11d0-a768-00aa006e0529}")
	DSReplicationGetChanges                 = uuid.UUID{0x11, 0x31, 0xf6, 0xaa, 0x9c, 0x07, 0x11, 0xd1, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	DSReplicationGetChangesAll              = uuid.UUID{0x11, 0x31, 0xf6, 0xad, 0x9c, 0x07, 0x11, 0xd1, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	DSReplicationSyncronize                 = uuid.UUID{0x11, 0x31, 0xf6, 0xab, 0x9c, 0x07, 0x11, 0xd1, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	DSReplicationGetChangesInFilteredSet, _ = uuid.FromString("{89e95b76-444d-4c62-991a-0facbeda640c}")

	AttributeMember                = uuid.UUID{0xbf, 0x96, 0x79, 0xc0, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	AttributeSetGroupMembership, _ = uuid.FromString("{BC0AC240-79A9-11D0-9020-00C04FC2D4CF}")
	AttributeSIDHistory            = uuid.UUID{0x17, 0xeb, 0x42, 0x78, 0xd1, 0x67, 0x11, 0xd0, 0xb0, 0x02, 0x00, 0x00, 0xf8, 0x03, 0x67, 0xc1}

	AttributeAllowedToActOnBehalfOfOtherIdentity, _ = uuid.FromString("{3F78C3E5-F79A-46BD-A0B8-9D18116DDC79}")
	AttributeAllowedToDelegateTo, _                 = uuid.FromString("{800d94d7-b7a1-42a1-b14d-7cae1423d07f}")

	AttributeMSDSGroupMSAMembership       = uuid.UUID{0x88, 0x8e, 0xed, 0xd6, 0xce, 0x04, 0xdf, 0x40, 0xb4, 0x62, 0xb8, 0xa5, 0x0e, 0x41, 0xba, 0x38}
	AttributeGPLink, _                    = uuid.FromString("{F30E3BBE-9FF0-11D1-B603-0000F80367C1}")
	AttributeMSDSKeyCredentialLink, _     = uuid.FromString("{5B47D60F-6090-40B2-9F37-2A4DE88F3063}")
	AttributeSecurityGUIDGUID, _          = uuid.FromString("{bf967924-0de6-11d0-a285-00aa003049e2}")
	AttributeAltSecurityIdentitiesGUID, _ = uuid.FromString("{00FBF30C-91FE-11D1-AEBC-0000F80367C1}")
	AttributeProfilePathGUID, _           = uuid.FromString("{bf967a05-0de6-11d0-a285-00aa003049e2}")
	AttributeScriptPathGUID, _            = uuid.FromString("{bf9679a8-0de6-11d0-a285-00aa003049e2}")
	AttributeMSDSManagedPasswordId, _     = uuid.FromString("{0e78295a-c6d3-0a40-b491-d62251ffa0a6}")
	AttributeUserAccountControlGUID, _    = uuid.FromString("{bf967a68-0de6-11d0-a285-00aa003049e2}")
	AttributePwdLastSetGUID, _            = uuid.FromString("{bf967a0a-0de6-11d0-a285-00aa003049e2}")
	ExtendedRightApplyGroupPolicy, _      = uuid.FromString("{edacfd8f-ffb3-11d1-b41d-00a0c968f939}")

	ExtendedRightCertificateEnroll, _     = uuid.FromString("{0e10c968-78fb-11d2-90d4-00c04f79dc55}")
	ExtendedRightCertificateAutoEnroll, _ = uuid.FromString("{a05b8cc2-17bc-4802-a710-e7c15ab866a2}")

	ValidateWriteSelfMembership, _ = uuid.FromString("{bf9679c0-0de6-11d0-a285-00aa003049e2}")
	ValidateWriteSPN, _            = uuid.FromString("{f3a64788-5306-11d1-a9c5-0000f80367c1}")

	ObjectGuidUser, _            = uuid.FromString("{bf967aba-0de6-11d0-a285-00aa003049e2")
	ObjectGuidComputer, _        = uuid.FromString("{bf967a86-0de6-11d0-a285-00aa003049e2")
	ObjectGuidGroup, _           = uuid.FromString("{bf967a9c-0de6-11d0-a285-00aa003049e2")
	ObjectGuidDomain, _          = uuid.FromString("{19195a5a-6da0-11d0-afd3-00c04fd930c9")
	ObjectGuidDNSZone, _         = uuid.FromString("{e0fa1e8b-9b45-11d0-afdd-00c04fd930c9")
	ObjectGuidDNSNode, _         = uuid.FromString("{e0fa1e8c-9b45-11d0-afdd-00c04fd930c9")
	ObjectGuidGPO, _             = uuid.FromString("{f30e3bc2-9ff0-11d1-b603-0000f80367c1")
	ObjectGuidOU, _              = uuid.FromString("{bf967aa5-0de6-11d0-a285-00aa003049e2")
	ObjectGuidAttributeSchema, _ = uuid.FromString("{BF967A80-0DE6-11D0-A285-00AA003049E2}")

	NetBIOSName = engine.NewAttribute("nETBIOSName")
	NCName      = engine.NewAttribute("nCName")
	DNSRoot     = engine.NewAttribute("dnsRoot")

	MemberOfIndirect = engine.NewAttribute("memberOfIndirect")

	ObjectTypeMachine = engine.NewObjectType("Machine", "Machine")
	DomainJoinedSID   = engine.NewAttribute("domainJoinedSid").Flag(engine.Single)
	DnsHostName       = engine.NewAttribute("dnsHostName")

	EdgeAuthenticatesAs  = engine.NewEdge("AuthenticatesAs")
	EdgeInheritsSecurity = engine.NewEdge("InheritsSecurity").SetDefault(true, true, false)
	EdgeRBCD             = engine.NewEdge("RBConstrainedDeleg")

	CertificateTemplates   = engine.NewAttribute("certificateTemplates")
	PublishedBy            = engine.NewAttribute("publishedBy")
	PublishedByDnsHostName = engine.NewAttribute("publishedByDnsHostName")

	msLAPSEncryptedPasswordAttributesGUID, _ = uuid.FromString("{f3531ec6-6330-4f8e-8d39-7a671fbac605}")

	EdgeMachineAccount = engine.NewEdge("MachineAccount").RegisterProbabilityCalculator(activedirectory.FixedProbability(-1)).Describe("Indicates this is the domain joined computer account belonging to the machine")

	// Fixme, double defined
	EdgeSessionService = engine.NewEdge("SessionService").RegisterProbabilityCalculator(activedirectory.FixedProbability(30)).Tag("Pivot").Describe("Account detected as running a service on machine")
)

type downLevelDomainInfo struct {
	suffix string
	name   string
}

func downLevelDomainMappings(tx *engine.Tx) []downLevelDomainInfo {
	results, found := tx.FindMulti(engine.ObjectClass, engine.NV("crossRef"))
	if !found {
		ui.Error().Msg("No domainDNS object found, can't apply DownLevelLogonName to objects")
		return nil
	}

	domains := make([]downLevelDomainInfo, 0, results.Len())
	results.Iterate(func(o *engine.Node) bool {
		dn := o.OneAttrString(NCName)
		netbiosname := o.OneAttrString(NetBIOSName)
		if dn == "" || netbiosname == "" {
			return true
		}

		domains = append(domains, downLevelDomainInfo{
			suffix: dn,
			name:   netbiosname,
		})
		return true
	})

	if len(domains) == 0 {
		ui.Error().Msg("No NCName to NetBIOSName mapping found, can't apply DownLevelLogonName to objects")
		return nil
	}

	sort.Slice(domains, func(i, j int) bool {
		return len(domains[i].suffix) > len(domains[j].suffix)
	})

	return domains
}

func applyDownLevelLogonNamePatches(tx *engine.Tx) {
	domains := downLevelDomainMappings(tx)
	if len(domains) == 0 {
		return
	}

	tx.Iterate(func(o *engine.Node) bool {
		if !o.HasAttr(engine.SAMAccountName) {
			return true
		}

		dn := o.DN()
		for _, domain := range domains {
			if strings.HasSuffix(dn, domain.suffix) {
				tx.Node(o).Set(engine.DownLevelLogonName, engine.NV(domain.name+"\\"+o.OneAttrString(engine.SAMAccountName)))
				break
			}
		}
		return true
	})
}

func applyDomainContextPatches(tx *engine.Tx) {
	tx.Iterate(func(o *engine.Node) bool {
		if o.DN() == "" || o.HasAttr(engine.DomainContext) {
			return true
		}

		parts := strings.Split(o.DN(), ",")
		lastpart := -1
		for i := len(parts) - 1; i >= 0; i-- {
			part := parts[i]
			if len(part) < 3 || !strings.EqualFold("dc=", part[:3]) {
				break
			}
			if strings.EqualFold("DC=ForestDNSZones", part) || strings.EqualFold("DC=DomainDNSZones", part) {
				break
			}
			lastpart = i
		}

		if lastpart != -1 {
			tx.Node(o).Set(engine.DomainContext, engine.NV(strings.Join(parts[lastpart:], ",")))
		}
		return true
	})
}

func applyObjectClassAndCategoryPatches(tx *engine.Tx) {
	tx.Iterate(func(object *engine.Node) bool {
		objectclasses := object.Attr(engine.ObjectClass)
		if objectclasses.Len() > 0 {
			guids := make([]engine.AttributeValue, 0, objectclasses.Len())
			objectclasses.Iterate(func(class engine.AttributeValue) bool {
				if oto, found := schemaObject(tx, object, engine.LDAPDisplayName, class); found {
					if guid := oto.OneAttr(activedirectory.SchemaIDGUID); guid.IsNil() {
						ui.Debug().Msgf("%v", oto)
						ui.Fatal().Msgf("Could not translate SchemaIDGUID for class %v - I need a Schema to work properly", class)
					} else {
						guids = append(guids, guid)
					}
				} else {
					ui.Warn().Msgf("Could not resolve object class %v, perhaps you didn't get a dump of the schema?", class.String())
				}
				return true
			})
			tx.Node(object).Set(engine.ObjectClassGUIDs, guids...)
		}

		objectcategoryguid := engine.NV(engine.UnknownGUID)
		simple := engine.NV("Unknown")
		typedn := object.OneAttr(engine.ObjectCategory)

		if !typedn.IsNil() {
			if oto, found := tx.Find(engine.DistinguishedName, typedn); found {
				if _, ok := oto.OneAttrGUID(activedirectory.SchemaIDGUID); ok {
					objectcategoryguid = oto.OneAttr(activedirectory.SchemaIDGUID)
					simple = oto.OneAttr(activedirectory.Name)
				} else {
					ui.Error().Msgf("Could not translate SchemaIDGUID for %v", typedn)
				}
			} else {
				ui.Error().Msgf("Could not resolve object category %v, perhaps you didn't get a dump of the schema?", typedn)
			}
		}

		tx.Node(object).SetFlex(engine.ObjectCategoryGUID, objectcategoryguid,
			engine.Type, simple,
		)
		return true
	})
}

func applyProtectedUserTags(tx *engine.Tx) {
	tx.Iterate(func(object *engine.Node) bool {
		if object.SID().Component(2) == 21 && object.SID().RID() == 525 {
			tx.EdgeIteratorRecursive(object, engine.In, engine.EdgeBitmap{}.Set(activedirectory.EdgeMemberOfGroup), true, func(source, member *engine.Node, edge engine.EdgeBitmap, depth int) bool {
				if member.Type() == engine.NodeTypeComputer || member.Type() == engine.NodeTypeUser {
					tx.Node(member).Tag("protected_user")
				}
				return true
			})
		}
		return true
	})
}

func applyWellKnownSIDDisplayNames(tx *engine.Tx) {
	tx.Iterate(func(o *engine.Node) bool {
		if o.HasAttr(engine.ObjectSid) && !o.HasAttr(engine.DisplayName) {
			if name, found := windowssecurity.KnownSIDs[o.SID().String()]; found {
				tx.Node(o).SetFlex(engine.DisplayName, name)
			}
		}
		return true
	})
}

func applyIndirectMemberOfPatches(tx *engine.Tx) {
	groupToMemberGraph := graph.NewGraph[*engine.Node, engine.EdgeBitmap]()

	tx.Iterate(func(group *engine.Node) bool {
		if group.Type() == engine.NodeTypeGroup && group.HasAttr(activedirectory.DistinguishedName) {
			tx.IterateEdges(group, engine.In, func(member *engine.Node, edge engine.EdgeBitmap) bool {
				if edge.IsSet(activedirectory.EdgeMemberOfGroup) {
					groupToMemberGraph.AddEdge(group, member, edge)
				}
				return true
			})
		}
		return true
	})

	scc := groupToMemberGraph.SCCKosaraju()
	dag := graph.CollapseSCCs(scc, groupToMemberGraph)

	sccReach := make([]map[int]int, len(dag.Nodes))
	for i := range dag.Nodes {
		sccReach[i] = make(map[int]int, 4)
		sccReach[i][i] = 0
	}

	topo := graph.TopoSortDAG(dag)
	for i := len(topo) - 1; i >= 0; i-- {
		sccIdx := topo[i]
		for succ := range dag.Edges[sccIdx] {
			if _, seen := sccReach[sccIdx][succ]; seen {
				continue
			}
			sccReach[sccIdx][succ] = 1
			for r, d := range sccReach[succ] {
				newDist := d + 1
				if existing, exists := sccReach[sccIdx][r]; !exists || newDist < existing {
					sccReach[sccIdx][r] = newDist
				}
			}
		}
	}

	groupList := make([]engine.AttributeValue, 0, 32)
	for i, sccNodes := range dag.Nodes {
		for _, group := range sccNodes {
			groupList = groupList[:0]
			for reachIdx, distance := range sccReach[i] {
				if distance > 1 {
					for _, member := range dag.Nodes[reachIdx] {
						if member == group {
							continue
						}
						if dn := member.OneAttr(engine.DistinguishedName); !dn.IsNil() {
							groupList = append(groupList, dn)
						}
					}
				}
			}

			if len(groupList) > 0 {
				tx.Node(group).Set(MemberOfIndirect, groupList...)
			}
		}
	}
}

func addDomainDNSDCSyncEdges(tx *engine.Tx) {
	tx.Iterate(func(o *engine.Node) bool {
		if o.Type() != engine.NodeTypeDomainDNS {
			return true
		}
		if !o.HasAttr(activedirectory.SystemFlags) {
			return true
		}
		sd, err := o.SecurityDescriptor()
		if err != nil {
			return true
		}

		var dcsync engine.TxNode
		if dn := o.DN(); dn != "" {
			dcsync, _ = tx.FindTwoOrAdd(
				engine.Type, engine.NodeTypeCallableServicePoint.ValueString(),
				engine.DistinguishedName, engine.NV("CN=DCsync,"+dn),
			)
			dcsync.Set(engine.Name, engine.NV("DCsync"))
			dcsync.Set(engine.DomainContext, engine.NV(o.OneAttrString(engine.DomainContext)))
			dcsync.Tag("hvt")
			tx.EdgeBecause(o, dcsync, activedirectory.EdgeControls, Inferred("a domain's replication service"))
		} else {
			ui.Warn().Msg("Cannot scope DCSync service for a domain without a distinguished name; retaining replication rights only")
		}

		type replicationRights struct{ changes, changesAll bool }
		rights := make(map[windowssecurity.SID]replicationRights)

		for index, acl := range sd.DACL.Entries {
			granted := rights[acl.SID]
			if ACEGrants(tx, sd, index, o, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationSyncronize) {
				tx.EdgeBecause(aceTrustee(tx, sd, acl.SID, o), o, activedirectory.EdgeDSReplicationSyncronize, ACECause(index, acl))
			}
			if ACEGrants(tx, sd, index, o, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChanges) {
				tx.EdgeBecause(aceTrustee(tx, sd, acl.SID, o), o, activedirectory.EdgeDSReplicationGetChanges, ACECause(index, acl))
				granted.changes = true
			}
			if ACEGrants(tx, sd, index, o, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChangesAll) {
				tx.EdgeBecause(aceTrustee(tx, sd, acl.SID, o), o, activedirectory.EdgeDSReplicationGetChangesAll, ACECause(index, acl))
				granted.changesAll = true
			}
			if ACEGrants(tx, sd, index, o, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChangesInFilteredSet) {
				tx.EdgeBecause(aceTrustee(tx, sd, acl.SID, o), o, activedirectory.EdgeDSReplicationGetChangesInFilteredSet, ACECause(index, acl))
			}

			if granted.changes || granted.changesAll {
				rights[acl.SID] = granted
			}
		}
		for sid, granted := range rights {
			if dcsync.Valid() && granted.changes && granted.changesAll {
				tx.EdgeBecause(aceTrustee(tx, sd, sid, o), dcsync, activedirectory.EdgeCall, RightsCause(o, "Replicating Directory Changes and Replicating Directory Changes All"))
			}
		}

		return true
	})
}

func addMachinesAffectedByGPO(tx *engine.Tx) {
	// The parsed gPLink of each scope of management, shared by all machines.
	linkCache := map[*engine.Node]engine.AttributeValues{}
	tx.Iterate(func(machine *engine.Node) bool {
		if machine.Type() != ObjectTypeMachine {
			return true
		}

		DomainJoinedSID := machine.OneAttr(attrs.DomainJoinedSID)
		if DomainJoinedSID.IsNil() {
			// Not domain joined, or only known by address (a logon source
			// that matches no known machine): no GPO applies to it.
			return true
		}

		computer, found := tx.Find(engine.ObjectSid, DomainJoinedSID)
		if !found || computer == nil {
			if computers, found := tx.FindMulti(engine.ObjectSid, DomainJoinedSID); found {
				ui.Warn().Msgf("Machine %v with DomainJoinedSID %v has multiple computer accounts", machine.OneAttrString(engine.Name), DomainJoinedSID)
				computers.Iterate(func(o *engine.Node) bool {
					ui.Warn().Msgf("Computer - %v (id %v)", o.DN(), o.ID())
					return true
				})
				return true
			}
			ui.Warn().Msgf("Machine %v with DomainJoinedSID %v has no computer account", machine.OneAttrString(engine.Name), DomainJoinedSID)
			return true
		}

		// The machine's own policy results are the confirmed outcome. When
		// they were collected, the import already linked the applied GPOs,
		// and they replace what the directory implies.
		if machine.HasAttr(localmachine.GPOResultsCollected) {
			tx.Node(machine).Tag("gpo_results_collected")
			return true
		}

		computerToken := gpoAccessToken(computer, tx)

		allowEnforcedGPOsOnly := false
		// applySOM applies the GPO links of one scope of management (an OU,
		// the domain or a site), in the order MS-GPOL 3.2.5.1.5 walks them.
		applySOM := func(som *engine.Node) {
			var gpcachelinks engine.AttributeValues
			var found bool
			if gpcachelinks, found = linkCache[som]; !found {
				// Syntax errors and links to GPOs that are not found are
				// reported by tagBrokenGPOLinks.
				links, _ := parseGPLink(som.OneAttrString(activedirectory.GPLink))
				for _, link := range links {
					if gpo, found := tx.Find(engine.DistinguishedName, engine.NV(link.dn)); found {
						gpcachelinks = append(gpcachelinks, engine.NV(gpo), engine.NV(link.options))
					}
				}
				linkCache[som] = gpcachelinks
			}

			for i := 0; i < gpcachelinks.Len(); i += 2 {
				gpo := gpcachelinks[i].Raw().(*engine.Node)
				gpLinkOptions := gpcachelinks[i+1].Raw().(int64)
				if gpLinkOptions&0x01 != 0 {
					continue
				}
				if allowEnforcedGPOsOnly && gpLinkOptions&0x02 == 0 {
					continue
				}
				if !computerPolicyEnabled(gpo) {
					continue
				}

				canRead := canReadGPO(gpo, computerToken, tx)
				canApply := canApplyGPO(gpo, computerToken, tx)
				if canRead && canApply {
					tx.EdgeBecause(gpo, machine, activedirectory.EdgeAffectedByGPO, engine.Source{Kind: SourceGPO, About: gpo, Detail: "linked above the computer, which can read and apply it"})
				}
			}
			if som.OneAttrString(activedirectory.GPOptions) == "1" {
				allowEnforcedGPOsOnly = true
			}
		}

		currentObject := computer
		var hasparent bool

		for {
			potentialParent := currentObject.Parent()
			if potentialParent != nil && potentialParent.DN() != "" && strings.HasSuffix(currentObject.DN(), potentialParent.DN()) {
				currentObject = potentialParent
			} else {
				currentObject, hasparent = tx.DistinguishedParent(currentObject)
				if !hasparent {
					break
				}
			}

			applySOM(currentObject)
		}

		// The site comes last in the walk (MS-GPOL 3.2.5.1.4).
		if site := machineSite(tx, machine, computer); site != nil {
			applySOM(site)
		}

		return true
	})
}

// gpoAccessToken approximates the security token the computer presents when
// it reads its policy: its own SID, every group it is a member of directly or
// transitively, and the well-known groups every authenticated computer has.
func gpoAccessToken(computer *engine.Node, ao engine.GraphReader) map[windowssecurity.SID]struct{} {
	token := map[windowssecurity.SID]struct{}{
		windowssecurity.EveryoneSID:           {},
		windowssecurity.AuthenticatedUsersSID: {},
		windowssecurity.ThisOrganizationSID:   {},
	}
	if sid := computer.SID(); !sid.IsBlank() {
		token[sid] = struct{}{}
	}
	for sid := range memberSIDs(ao, computer) {
		token[sid] = struct{}{}
	}
	return token
}

// canReadGPO reports whether the token can read the GPO's attributes, which
// the client needs for the GPO to be returned by its search (MS-GPOL 3.2.5.1.5).
func canReadGPO(gpo *engine.Node, token map[windowssecurity.SID]struct{}, ao engine.GraphReader) bool {
	return tokenHasGPOAccess(gpo, token, ao, uuid.Nil, engine.RIGHT_DS_READ_PROPERTY)
}

func addGMSAPasswordReadEdges(tx *engine.Tx) {
	tx.Iterate(func(o *engine.Node) bool {
		o.Attr(activedirectory.MSDSGroupMSAMembership).Iterate(func(msads engine.AttributeValue) bool {
			if sd, ok := msads.Raw().(*engine.SecurityDescriptor); ok && sd != nil {
				for index, acl := range sd.DACL.Entries {
					if TrusteeGranted(tx, sd, acl.SID, o, engine.RIGHT_DS_READ_PROPERTY, uuid.Nil) {
						tx.EdgeBecause(aceTrustee(tx, sd, acl.SID, o), o, activedirectory.EdgeReadGMSAPassword, DescriptorACECause(activedirectory.MSDSGroupMSAMembership, index, acl))
					}
				}
			}
			return true
		})
		return true
	})
}

// Missing metadata in older collections is unknown, not an explicit disable.
func computerPolicyEnabled(gpo *engine.Node) bool {
	if flags, ok := gpo.AttrInt(gpoFlags); ok && flags&2 != 0 {
		return false
	}
	if version, ok := gpo.AttrInt(gpoDirectoryVersion); ok && version == 0 {
		if fileVersion, known := gpo.AttrInt(gpoFileVersion); known && fileVersion == 0 {
			return false
		}
	}
	if functionality, ok := gpo.AttrInt(gpoFunctionalityVersion); ok && functionality != 2 {
		return false
	}
	return true
}

// canApplyGPO reports whether the token is granted, and not denied, the
// Apply Group Policy extended right (MS-GPOL 3.2.5.1.6 step 3).
func canApplyGPO(gpo *engine.Node, token map[windowssecurity.SID]struct{}, ao engine.GraphReader) bool {
	return tokenHasGPOAccess(gpo, token, ao, ExtendedRightApplyGroupPolicy, engine.RIGHT_DS_CONTROL_ACCESS)
}

func tokenHasGPOAccess(gpo *engine.Node, token map[windowssecurity.SID]struct{}, ao engine.GraphReader, guid uuid.UUID, mask engine.Mask) bool {
	sd, err := gpo.SecurityDescriptor()
	if err != nil || sd == nil {
		return true
	}
	return sd.AccessCheck(func(sid windowssecurity.SID) bool {
		_, ok := token[sid]
		return ok
	}, gpo, mask, guid, ao.Graph())
}

func resolveMemberOfAndMember(tx *engine.Tx) {
	tx.Iterate(func(object *engine.Node) bool {
		object.Attr(activedirectory.MemberOf).Iterate(func(memberof engine.AttributeValue) bool {
			group, found := tx.Find(engine.DistinguishedName, memberof)
			if !found {
				var sid engine.AttributeValue
				if stringsid, _, found := strings.Cut(memberof.String(), ",CN=ForeignSecurityPrincipals,"); found {
					if c, err := windowssecurity.ParseStringSID(stringsid); err == nil {
						sid = engine.NV(c)
					}
					ui.Info().Msgf("Missing Foreign-Security-Principal: %v is a member of %v, which is not found - adding enhanced synthetic group", object.DN(), memberof)
				} else {
					ui.Warn().Msgf("Possible hardening? %v is a member of %v, which is not found - adding synthetic group. Your analysis will be degraded, try dumping with Domain Admin rights.", object.DN(), memberof)
				}
				group = engine.NewNode(
					engine.IgnoreBlanks,
					engine.DistinguishedName, memberof,
					engine.Type, engine.NV("Group"),
					engine.ObjectClass, engine.NV("top"), engine.NV("group"),
					engine.Name, engine.NV("Synthetic group "+memberof.String()),
					engine.Description, engine.NV("Synthetic group"),
					engine.ObjectSid, sid,
					engine.DataLoader, engine.NV("Autogenerated"),
				)
				tx.Add(group)
			}
			tx.EdgeBecause(object, group, activedirectory.EdgeMemberOfGroup, AttributeCause(object, activedirectory.MemberOf))
			return true
		})

		object.Attr(activedirectory.Member).Iterate(func(member engine.AttributeValue) bool {
			var memberobject engine.NodeRef
			if found, ok := tx.Find(engine.DistinguishedName, member); ok {
				memberobject = found
			} else {
				if stringsid, _, found := strings.Cut(member.String(), ",CN=ForeignSecurityPrincipals,"); found {
					stringsid, _, _ = strings.Cut(stringsid[3:], "\\")

					if sid, err := windowssecurity.ParseStringSID(stringsid); err == nil {
						memberobject = tx.FindOrAddAdjacentSID(sid, object)
					} else {
						ui.Warn().Msgf("Could not extract SID from Foreign-Security-Principal %v: %v", member.String(), err)
					}
				}
				if memberobject == nil {
					ui.Warn().Msgf("Possible hardening? %v is a member of %v, which is not found - adding synthetic member. Your analysis will be degraded, try dumping with Domain Admin rights.", member, object.DN())
					memberobject, _ = tx.FindOrAdd(engine.DistinguishedName, member,
						engine.DataLoader, "Autogenerated",
					)
				}
			}
			tx.EdgeBecause(memberobject, object, activedirectory.EdgeMemberOfGroup, AttributeCause(object, activedirectory.Member))
			return true
		})
		return true
	})
}

func addRBCDEdges(tx *engine.Tx) {
	tx.Iterate(func(o *engine.Node) bool {
		if o.Type() != engine.NodeTypeComputer && o.Type() != engine.NodeTypeUser {
			return true
		}
		o.Attr(activedirectory.MSDSAllowedToActOnBehalfOfOtherIdentity).Iterate(func(val engine.AttributeValue) bool {
			if sd, ok := val.Raw().(*engine.SecurityDescriptor); ok {
				for index, acl := range sd.DACL.Entries {
					if ACEGrants(tx, sd, index, o, engine.RIGHT_DS_CONTROL_ACCESS, uuid.Nil) {
						tx.EdgeBecause(aceTrustee(tx, sd, acl.SID, o), o, EdgeRBCD, DescriptorACECause(activedirectory.MSDSAllowedToActOnBehalfOfOtherIdentity, index, acl))
					}
				}
			}
			return true
		})
		return true
	})
}

func init() {
	LoaderID.AddProcessor(func(tx *engine.Tx) {
		tx.Iterate(func(o *engine.Node) bool {
			if o.Type() == engine.NodeTypeGroupPolicyContainer {
				if identity := activedirectory.GPOIdentityFromDN(o.DN()); identity != "" {
					tx.Node(o).Set(activedirectory.GPOIdentity, engine.NV(identity))
				}
			}
			return true
		})
	}, engine.Processor{
		Description: "GPO identity from its distinguished name, which GPO collections and machine policy results resolve to",
		Phase:       engine.LoaderPhase,
		Needs:       []engine.Product{ProductNodeTypes},
	})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		// LAPS v1 extends each forest's schema with its own GUID.
		type lapsSchema struct {
			guid       uuid.UUID
			readRights engine.Mask
		}
		schemas := newPerDump(func(o *engine.Node) lapsSchema {
			lapsobject, found := schemaObjectTwo(tx, o, engine.Name, engine.NV("ms-Mcs-AdmPwd"),
				engine.ObjectClass, engine.NV("attributeSchema"))
			if !found {
				return lapsSchema{}
			}
			guid, ok := lapsobject.OneAttrRaw(activedirectory.SchemaIDGUID).(uuid.UUID)
			if !ok {
				ui.Error().Msgf("Could not read LAPS schema extension GUID from %v", lapsobject.DN())
				return lapsSchema{}
			}
			return lapsSchema{guid, AttributeReadRights(tx, o, guid, true)}
		})

		tx.Iterate(func(o *engine.Node) bool {
			// Only for computers
			if o.Type() != engine.NodeTypeComputer {
				return true
			}

			// ... that has LAPS installed
			if !o.HasAttr(activedirectory.MSmcsAdmPwdExpirationTime) {
				return true
			}
			schema := schemas.For(o)
			if schema.guid.IsNil() {
				return true
			}

			// Analyze ACL
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return true
			}

			// Link to the machine object
			computerSid := o.SID()
			if computerSid.IsBlank() {
				ui.Fatal().Msgf("Computer account %v has no objectSID", o.DN())
			}
			machines := MachinesForComputer(tx, computerSid)
			if len(machines) == 0 {
				ui.Error().Msgf("Could not locate machine for domain SID %v while processing LAPS v1", computerSid)
				return true
			}
			for _, machine := range machines {
				tx.Node(machine).Tag("laps")
			}

			// ms-Mcs-AdmPwd is confidential, so reading it takes both read and
			// control access rights.
			for _, sid := range PrincipalsGranted(sd, o, schema.readRights, schema.guid, tx) {
				trustee := aceTrustee(tx, sd, sid, o)
				for _, machine := range machines {
					tx.EdgeBecause(trustee, machine, activedirectory.EdgeReadLAPSPassword, RightsCause(o, "read ms-Mcs-AdmPwd"))
				}
			}
			return true
		})
	}, engine.Processor{
		Description: "Reading local admin passwords via LAPS v1",
		Phase:       engine.AnalysisPhase,
		Needs:       []engine.Product{ProductMemberships, ProductMachines},
		Provides:    []engine.Product{ProductACLEdges},
	})

	LoaderID.AddProcessor(addLAPSv2Edges, engine.Processor{
		Description: "Reading local admin passwords via LAPS v2",
		Phase:       engine.AnalysisPhase,
		Needs:       []engine.Product{ProductMemberships, ProductMachines},
		Provides:    []engine.Product{ProductACLEdges},
	})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		tx.Iterate(func(o *engine.Node) bool {
			if o.Type() == engine.NodeTypeForeignSecurityPrincipal {
				return true
			}
			if sd, err := o.SecurityDescriptor(); err == nil && sd.Control&engine.CONTROLFLAG_DACL_PROTECTED == 0 {
				if parentobject, found := tx.DistinguishedParent(o); found {
					ui.Trace().Msgf("%v interits security from %v", o.DN(), parentobject.DN())
					tx.EdgeBecause(parentobject, o, EdgeInheritsSecurity, engine.Source{Kind: SourceACL, Detail: "DACL not protected from inheritance"})
				}
			}
			return true
		})
	}, engine.Processor{
		Description: "Indicator that object inherits security from the container it is within",
		Phase:       engine.LoaderPhase,
		Needs:       []engine.Product{ProductNodeTypes, ProductTree},
		Provides:    []engine.Product{ProductACLEdges},
	})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		tx.Iterate(func(o *engine.Node) bool {
			if o.Type() != engine.NodeTypeContainer || o.OneAttrString(engine.Name) != "Machine" {
				return true
			}
			// Only for computers, you can't really pwn users this way
			p, hasparent := tx.DistinguishedParent(o)
			if !hasparent || p.Type() != engine.NodeTypeGroupPolicyContainer {
				return true
			}
			tx.EdgeBecause(p, o, activedirectory.PartOfGPO, Inferred("container of a GPO"))
			return true
		})
	}, engine.Processor{
		Description: "Machine configurations that are part of a GPO",
		Phase:       engine.LoaderPhase,
		Needs:       []engine.Product{ProductNodeTypes, ProductTree},
		Provides:    []engine.Product{ProductGPOStructure},
	})

	matchMSOLDescription := regexp.MustCompile(`Account created by Microsoft Azure Active Directory Connect with installation identifier ([0-9a-f]+) running on computer ([^ ]+) configured to synchronize to tenant ([^ ]+)\. `)

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		tx.Iterate(func(o *engine.Node) bool {
			if o.Type() != engine.NodeTypeUser || !strings.HasPrefix(o.OneAttrString(engine.Name), "MSOL_") {
				return true
			}

			// Try to regexp match
			match := matchMSOLDescription.FindSubmatch([]byte(o.OneAttrString(engine.Description)))
			if match == nil {
				return true
			}

			// Extract the first match
			machineName := string(match[2])

			// Short names repeat across domains: prefer the account's own.
			machines, _ := tx.FindTwoMulti(engine.Type, ObjectTypeMachine.ValueString(),
				engine.Name, engine.NV(machineName))
			if machines.Len() > 1 {
				machines = sameDump(machines, o)
			}
			machine, found := oneOf(machines)

			if !found {
				ui.Warn().Msgf("%v detected as Azure Connect running on %v, but machine not found - not linking", o.OneAttrString(engine.Name), machineName)
				return true
			}

			tx.EdgeBecause(machine, o, EdgeSessionService, AttributeCause(o, engine.Description))
			return true
		})
	}, engine.Processor{
		Description: "Link MSOL_* accounts to computers running it from description",
		Phase:       engine.LoaderPhase,
		Needs:       []engine.Product{ProductNodeTypes, ProductMachines},
		Provides:    []engine.Product{ProductAccountLinks},
	})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		tx.Iterate(func(o *engine.Node) bool {
			if o.Type() != engine.NodeTypeContainer || o.OneAttrString(engine.Name) != "User" {
				return true
			}
			// Only for users, you can't really pwn users this way
			p, hasparent := tx.DistinguishedParent(o)
			if !hasparent || p.Type() != engine.NodeTypeGroupPolicyContainer {
				return true
			}
			tx.EdgeBecause(p, o, activedirectory.PartOfGPO, Inferred("container of a GPO"))
			return true
		})
	}, engine.Processor{
		Description: "User configurations that are part of a GPO",
		Phase:       engine.LoaderPhase,
		Needs:       []engine.Product{ProductNodeTypes, ProductTree},
		Provides:    []engine.Product{ProductGPOStructure},
	})

	LoaderID.AddProcessor(addACLRuleEdges, engine.Processor{
		Description: "Rights granted by ACLs (see aclEdgeRules)",
		Phase:       engine.AnalysisPhase,
		Needs:       []engine.Product{ProductMemberships},
		Provides:    []engine.Product{ProductACLEdges},
	})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		tx.Iterate(func(o *engine.Node) bool {
			// It's a group
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return true
			}
			for index, acl := range sd.DACL.Entries {
				if acl.Type == engine.ACETYPE_ACCESS_DENIED || acl.Type == engine.ACETYPE_ACCESS_DENIED_OBJECT {
					tx.EdgeBecause(aceTrustee(tx, sd, acl.SID, o), o, activedirectory.EdgeACLContainsDeny, ACECause(index, acl)) // Not a probability of success, this is just an indicator
				}
			}
			return true
		})
	}, engine.Processor{
		Description: "Indicator for possible false positives, as the ACL contains DENY entries",
		Phase:       engine.AnalysisPhase,
		Needs:       []engine.Product{ProductMemberships},
		Provides:    []engine.Product{ProductACLEdges},
	})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		// Find dsHeuristics, this defines groups EXCLUDED From AdminSDHolder application
		// https://social.technet.microsoft.com/wiki/contents/articles/22331.adminsdholder-protected-groups-and-security-descriptor-propagator.aspx#What_is_a_protected_group
		blocked := map[string]bool{} // per domain context
		tx.Iterate(func(o *engine.Node) bool {
			sd, err := o.SecurityDescriptor()
			if err != nil || sd.Owner.IsNull() {
				return true
			}
			// Any ACE for OWNER RIGHTS replaces the owner's implicit rights.
			if hasOwnerRightsACE(sd) {
				return true
			}
			// BlockOwnerImplicitRights takes them away on computer objects.
			// The spec exempts owners in Domain Admins or Enterprise Admins;
			// memberships are not resolved yet here, and those owners have
			// full control through other edges anyway.
			if o.Type() == engine.NodeTypeComputer {
				domainContext := o.OneAttrString(engine.DomainContext)
				block, known := blocked[domainContext]
				if !known {
					block = blocksOwnerImplicitRights(forestHeuristics(tx, domainContext))
					blocked[domainContext] = block
				}
				if block {
					return true
				}
			}
			tx.EdgeBecause(tx.FindOrAddAdjacentSID(sd.Owner, o), o, activedirectory.EdgeOwns, OwnerCause())
			return true
		})
	}, engine.Processor{
		Description: "Indicator that someone owns an object",
		Phase:       engine.AnalysisPhase,
		Needs:       []engine.Product{ProductMemberships},
		Provides:    []engine.Product{ProductACLEdges},
	})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		kerberoast := "kerberoast"

		tx.Iterate(func(o *engine.Node) bool {
			// Only computers and users
			if o.Type() != engine.NodeTypeUser {
				return true
			}
			if o.Attr(activedirectory.ServicePrincipalName).Len() > 0 && !accountDisabled(o) {
				tx.Node(o).Tag(kerberoast)
			}
			return true
		})
	}, engine.Processor{
		Description: "Indicator that a user has a ServicePrincipalName and an authenticated user can Kerberoast it",
		Phase:       engine.LoaderPhase,
		Needs:       []engine.Product{ProductNodeTypes},
		Provides:    []engine.Product{ProductAccountAttacks},
	})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		tx.Iterate(func(o *engine.Node) bool {
			if o.Type() != engine.NodeTypeUser {
				return true
			}
			if o.Attr(activedirectory.ServicePrincipalName).Len() > 0 && !accountDisabled(o) {
				// Authenticated Users of the account's own domain
				if authusers, found := tx.FindAdjacentSID(windowssecurity.AuthenticatedUsersSID, o); found {
					tx.EdgeBecause(authusers, o, activedirectory.EdgeHasSPN, AttributeCause(o, activedirectory.ServicePrincipalName))
				} else {
					ui.Error().Msgf("Could not locate Authenticated Users for %v", o.DN())
				}
			}
			return true
		})
	}, engine.Processor{
		Description: "Kerberoast relationship edge",
		Phase:       engine.LoaderPhase,
		Needs:       []engine.Product{ProductNodeTypes, ProductWellKnownPrincipals},
		Provides:    []engine.Product{ProductAccountAttacks},
	})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		tx.Iterate(func(o *engine.Node) bool {
			// Only users
			if o.Type() != engine.NodeTypeUser {
				return true
			}
			if uac, ok := o.AttrInt(activedirectory.UserAccountControl); ok && uac&engine.UAC_DONT_REQ_PREAUTH != 0 {
				tx.Node(o).Tag("asreproast")
			}
			return true
		})
	}, engine.Processor{
		Description: "Indicator that a user has \"don't require preauth\" and can be ASREPRoasted",
		Phase:       engine.LoaderPhase,
		Needs:       []engine.Product{ProductNodeTypes, ProductWellKnownPrincipals},
		Provides:    []engine.Product{ProductAccountAttacks},
	})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		tx.Iterate(func(o *engine.Node) bool {
			if o.Type() != engine.NodeTypeUser {
				return true
			}
			if uac, ok := o.AttrInt(activedirectory.UserAccountControl); ok && uac&engine.UAC_DONT_REQ_PREAUTH != 0 {
				// Anonymous Logon of the account's own domain
				if anonymous, found := tx.FindAdjacentSID(windowssecurity.AnonymousLogonSID, o); found {
					tx.EdgeBecause(anonymous, o, activedirectory.EdgeDontReqPreauth, AttributeCause(o, activedirectory.UserAccountControl))
				}
			}
			return true
		})
	}, engine.Processor{
		Description: "ASREPRoast relationship edge",
		Phase:       engine.LoaderPhase,
		Needs:       []engine.Product{ProductNodeTypes, ProductWellKnownPrincipals},
		Provides:    []engine.Product{ProductAccountAttacks},
	})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		addRBCDEdges(tx)
	}, engine.Processor{
		Description: `Someone is listed in the msDS-AllowedToActOnBehalfOfOtherIdentity (Resource Based Constrained Delegation) on an account`,
		Phase:       engine.AnalysisPhase,
		Needs:       []engine.Product{ProductMemberships},
		Provides:    []engine.Product{ProductDelegation},
	})

	LoaderID.AddProcessor(addConstrainedDelegationEdges, engine.Processor{
		Description: `Constrained delegation to a service; without protocol transition a suitable forwardable ticket is also required`,
		Phase:       engine.LoaderPhase,
		Needs:       []engine.Product{ProductNodeTypes, ProductDomainContext, ProductMachines},
		Provides:    []engine.Product{ProductDelegation},
	})

	/*
		// https://blog.harmj0y.net/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/
		Loader.AddProcessor(func(ao *engine.Objects) {
			ao.Iterate(func(o *engine.Object) bool {
				// Only computers
				if o.Type() != engine.ObjectTypeComputer {
					return true
				}
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return true
				}
				for index, acl := range sd.DACL.Entries {
					if ACEGrants(ao, sd, index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeAllowedToDelegateTo) {
						// Also requires the SeEnableDelegationPrivilege set on the DC for the user doing it!!
						ao.EdgeTo(aceTrustee(ao, sd, acl.SID, o), o, activedirectory.EdgeWriteAllowedToDelegateTo) // Success rate?
					}
				}
				return true
			})
		}, `Modify the msDS-AllowedToDelegateTo (Constrained Delegation) on a computer to enable any SPN enabled user to impersonate anyone else`, engine.BeforeMergeFinal)
	*/
	LoaderID.AddProcessor(addGMSAPasswordReadEdges, engine.Processor{
		Description: "Allows someone to read a password of a managed service account",
		Phase:       engine.AnalysisPhase,
		Needs:       []engine.Product{ProductMemberships},
		Provides:    []engine.Product{ProductACLEdges},
	})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		tx.Iterate(func(o *engine.Node) bool {
			o.Attr(activedirectory.MSDSHostServiceAccount).Iterate(func(dn engine.AttributeValue) bool {
				if targetmsa, found := tx.Find(engine.DistinguishedName, dn); found {
					tx.EdgeBecause(o, targetmsa, activedirectory.EdgeHasMSA, AttributeCause(o, activedirectory.MSDSHostServiceAccount))
				}
				return true
			})
			return true
		})
	}, engine.Processor{
		Description: "Indicates that the object has a service account in use",
		Phase:       engine.LoaderPhase,
		Provides:    []engine.Product{ProductAccountLinks},
	})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		tx.Iterate(func(o *engine.Node) bool {
			o.Attr(activedirectory.SIDHistory).Iterate(func(sidval engine.AttributeValue) bool {
				if sid, ok := sidval.Raw().(windowssecurity.SID); ok {
					tx.EdgeBecause(o, tx.FindOrAddAdjacentSID(sid, o), activedirectory.EdgeSIDHistoryEquality, AttributeCause(o, activedirectory.SIDHistory))
				}
				return true
			})
			return true
		})
	}, engine.Processor{
		Description: "Indicates that object has a SID History attribute pointing to the other object, making them the 'same' permission wise",
		Phase:       engine.LoaderPhase,
		Needs:       []engine.Product{ProductDomainContext, ProductWellKnownPrincipals},
		Provides:    []engine.Product{ProductAccountLinks},
	})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		addDomainDNSDCSyncEdges(tx)
	}, engine.Processor{
		Description: "Permissions on DomainDNS objects leading to DCsync attacks",
		Phase:       engine.AnalysisPhase,
		Needs:       []engine.Product{ProductMemberships},
		Provides:    []engine.Product{ProductACLEdges},
	})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		// Ensure everyone has a family
		tx.Iterate(func(computeraccount *engine.Node) bool {
			if computeraccount.Type() != engine.NodeTypeComputer {
				return true
			}

			sid := computeraccount.OneAttr(engine.ObjectSid)
			if sid.IsNil() {
				ui.Error().Msgf("Computer account without SID: %v", computeraccount.DN())
				return true
			}
			machine, _ := tx.FindOrAdd(
				DomainJoinedSID, sid,
				engine.IgnoreBlanks,
				attrs.PrimaryMachineFor, sid,
				engine.Name, computeraccount.Attr(engine.Name),
				activedirectory.Type, ObjectTypeMachine.ValueString(),
				DnsHostName, computeraccount.Attr(DnsHostName),
			)
			// ui.Debug().Msgf("Added machine for SID %v", sid.String())

			tx.EdgeBecause(machine, computeraccount, EdgeAuthenticatesAs, Inferred("a machine authenticates as its computer account"))
			tx.EdgeBecause(machine, computeraccount, EdgeMachineAccount, Inferred("a machine authenticates as its computer account"))
			machine.ChildOf(computeraccount)

			return true
		})
	},
		engine.Processor{
			Description: "creating Machine objects (representing the machine running the OS)",
			Phase:       engine.LoaderPhase,
			Needs:       []engine.Product{ProductNodeTypes},
			Provides:    []engine.Product{ProductMachines},
		})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		// Ensure everyone has a family
		tx.Iterate(func(o *engine.Node) bool {
			potentialorphan := o
			for {
				if potentialorphan.Parent() != nil {
					return true
				}

				if potentialorphan == tx.Root() {
					return true
				}

				if parent, found := tx.DistinguishedParent(potentialorphan); found {
					tx.Node(potentialorphan).ChildOf(parent)
					return true
				}

				dn := potentialorphan.DN()
				if potentialorphan.Type() == engine.NodeTypeDomainDNS && len(dn) > 3 && strings.EqualFold("dc=", dn[:3]) {
					// Top of some AD we think, hook to top of browsable tree
					tx.Node(o).ChildOf(tx.Root())
					return true
				}

				// Create a synthetic parent
				parentdn := util.ParentDistinguishedName(potentialorphan.DN())
				if parentdn == "" {
					return true
				}

				ui.Debug().Msgf("AD object %v (%v) has no parent :-( - creating synthetic object", o.Label(), o.DN())

				newparent := tx.AddNew(
					engine.DistinguishedName, parentdn,
					engine.Description, "Synthetic parent object",
				)
				tx.Node(potentialorphan).ChildOf(newparent)
				potentialorphan = newparent.Node() // loop, to ensure new objects also have parents
			}
		})
	},
		engine.Processor{
			Description: "applying parent/child relationships",
			Phase:       engine.LoaderPhase,
			Needs:       []engine.Product{ProductNodeTypes, ProductMachines},
			Provides:    []engine.Product{ProductTree},
		})

	LoaderID.AddProcessor(applyDownLevelLogonNamePatches,
		engine.Processor{
			Description: "applying DownLevelLogonName attribute",
			Phase:       engine.LoaderPhase,
			Provides:    []engine.Product{ProductDownLevelLogonName},
		})

	LoaderID.AddProcessor(applyDomainContextPatches,
		engine.Processor{
			Description: "applying domain part attribute",
			Phase:       engine.LoaderPhase,
			Provides:    []engine.Product{ProductDomainContext},
		})

	LoaderID.AddProcessor(addAdminSDHolderEdges,
		engine.Processor{
			Description: "AdminSDHolder rights propagation indicator",
			Phase:       engine.AnalysisPhase,
			Needs:       []engine.Product{ProductMemberships},
			Provides:    []engine.Product{ProductAdminSDHolder},
		})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		// Add our known SIDs to every domain that lacks them
		for _, domain := range FindDomainNodes(tx) {
			for sid, name := range windowssecurity.KnownSIDs {
				binsid, err := windowssecurity.ParseStringSID(sid)
				if err != nil {
					ui.Fatal().Msgf("Problem parsing SID %v", sid)
				}
				dn := "CN=" + name + ",CN=microsoft-builtin"
				tx.FindOrAddAdjacentSID(binsid, domain,
					engine.DistinguishedName, engine.NV(dn),
					engine.Name, engine.NV(name),
					engine.ObjectSid, engine.NV(binsid),
					engine.ObjectClass, engine.NV("person"), engine.NV("user"), engine.NV("top"),
					engine.Type, engine.NV("Group"),
				)
			}
		}
	},
		engine.Processor{
			Description: "missing well-known SIDs",
			Phase:       engine.LoaderPhase,
			Needs:       []engine.Product{ProductNodeTypes, ProductDomainContext},
			Provides:    []engine.Product{ProductWellKnownPrincipals},
		})

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		// Generate member of chains, per domain
		type domainParts struct {
			authenticatedUsers engine.TxNode
			dcsync             engine.TxNode
		}
		domains := map[windowssecurity.SID]domainParts{}
		dnsRootOf := map[string]string{} // naming context -> DNS root
		for _, domainNode := range FindDomainNodes(tx) {
			ncname, netbiosname, dnsroot, domainsid, err := GetDomainInfo(domainNode, tx)
			if err != nil {
				ui.Warn().Msgf("Could not get needed domain information (%v), skipping domain", err)
				continue
			}
			everyone := tx.FindOrAddAdjacentSID(windowssecurity.EveryoneSID, domainNode)
			authenticatedusers := tx.FindOrAddAdjacentSID(windowssecurity.AuthenticatedUsersSID, domainNode)
			tx.EdgeBecause(authenticatedusers, everyone, activedirectory.EdgeMemberOfGroup, Inferred("Authenticated Users are part of Everyone"))

			dcsync, _ := tx.FindTwoOrAdd(
				engine.Name, engine.NV("DCsync"),
				engine.DomainContext, engine.NV(ncname),
				engine.Type, engine.NodeTypeCallableServicePoint.ValueString(),
			)
			dcsync.Tag("hvt")
			domains[domainsid] = domainParts{authenticatedusers, dcsync}
			dnsRootOf[strings.ToLower(ncname)] = strings.ToLower(dnsroot)

			TrustMap.Store(TrustPair{
				SourceNCName:  ncname,
				SourceDNSRoot: strings.ToLower(dnsroot),
				SourceNetbios: netbiosname,
				SourceSID:     domainsid.String(),
			}, TrustInfo{})
		}

		tx.Iterate(func(object *engine.Node) bool {
			// Objects without a domain SID (OUs, containers, DNS records,
			// built-in principals) belong to no collected domain.
			var domain domainParts
			var inCollectedDomain bool
			if sid := object.SID(); sid.Component(2) == 21 && sid.Components() > 4 {
				domain, inCollectedDomain = domains[sid.StripRID()]
			}
			if rid, ok := object.AttrInt(activedirectory.PrimaryGroupID); ok {
				sid := object.SID()
				if len(sid) > 8 {
					sidbytes := []byte(sid)
					binary.LittleEndian.PutUint32(sidbytes[len(sid)-4:], uint32(rid))
					primarygroup := tx.FindOrAddAdjacentSID(windowssecurity.SID(sidbytes), object)
					tx.EdgeBecause(object, primarygroup, activedirectory.EdgeMemberOfGroup, AttributeCause(object, activedirectory.PrimaryGroupID))
				}
			}

			// Crude special handling for Everyone and Authenticated Users
			if object.SID().Components() == 7 && inCollectedDomain && object.Type() != engine.NodeTypeGroup {
				tx.EdgeBecause(object, domain.authenticatedUsers, activedirectory.EdgeMemberOfGroup, Inferred("every account of a domain is an Authenticated User"))
			}

			if lastlogon, ok := object.AttrTime(activedirectory.LastLogonTimestamp); ok {
				tx.Node(object).Set(activedirectory.MetaLastLoginAge, engine.NV(int(time.Since(lastlogon)/time.Hour)))
			}
			if passwordlastset, ok := object.AttrTime(activedirectory.PwdLastSet); ok {
				tx.Node(object).Set(activedirectory.MetaPasswordAge, engine.NV(int(time.Since(passwordlastset)/time.Hour)))
			}
			if strings.Contains(strings.ToLower(object.OneAttrString(activedirectory.OperatingSystem)), "linux") {
				tx.Node(object).Tag("linux")
			}
			if strings.Contains(strings.ToLower(object.OneAttrString(activedirectory.OperatingSystem)), "windows") {
				tx.Node(object).Tag("windows")
			}
			if object.Attr(activedirectory.MSmcsAdmPwdExpirationTime).Len() > 0 {
				tx.Node(object).Tag("laps")
			}
			if object.HasAttr(activedirectory.MSDSAllowedToDelegateTo) {
				tx.Node(object).Tag("constrained")
			}
			if uac, ok := object.AttrInt(activedirectory.UserAccountControl); ok {
				if uac&engine.UAC_TRUSTED_FOR_DELEGATION != 0 {
					tx.Node(object).Tag("unconstrained")
				}
				if uac&engine.UAC_NOT_DELEGATED != 0 {
					tx.Node(object).Tag("nodelegation")
				}
				if uac&engine.UAC_WORKSTATION_TRUST_ACCOUNT != 0 {
					tx.Node(object).Tag("computer_account")
				}
				if uac&engine.UAC_SERVER_TRUST_ACCOUNT != 0 {
					tx.Node(object).Tag("domaincontroller_account")

					// All DCs are members of Enterprise Domain Controllers
					tx.EdgeBecause(object, tx.FindOrAddAdjacentSID(windowssecurity.EnterpriseDomainControllers, object), activedirectory.EdgeMemberOfGroup, AttributeCause(object, activedirectory.UserAccountControl))

					if inCollectedDomain {
						tx.EdgeBecause(object, domain.dcsync, activedirectory.EdgeCall, Inferred("domain controllers replicate the directory"))
					}

					// Also they can DCsync because of this membership ... FIXME
				}

				var expired, disabled bool
				disabled = uac&engine.UAC_ACCOUNTDISABLE != 0
				if disabled {
					tx.Node(object).Tag("account_disabled")
				} else {
					tx.Node(object).Tag("account_enabled")
				}

				if uac&engine.UAC_LOCKOUT != 0 {
					tx.Node(object).Tag("account_locked")
				}

				if object.HasAttr(activedirectory.AccountExpires) {
					if exp, ok := object.Attr(activedirectory.AccountExpires).First().Raw().(time.Time); ok {
						if !exp.IsZero() && time.Now().After(exp) {
							tx.Node(object).Tag("account_expired")
							expired = true
						}
					}
				}

				if disabled || expired {
					tx.Node(object).Tag("account_inactive")
				} else {
					tx.Node(object).Tag("account_active")
				}
				if uac&engine.UAC_PASSWD_CANT_CHANGE != 0 {
					tx.Node(object).Tag("password_cant_change")
				}
				if uac&engine.UAC_DONT_EXPIRE_PASSWORD != 0 {
					tx.Node(object).Tag("password_never_expires")
				}
				if uac&engine.UAC_PASSWD_NOTREQD != 0 {
					tx.Node(object).Tag("password_not_required")
				}

				if uac&engine.UAC_SERVER_TRUST_ACCOUNT != 0 {
					// Domain Controller
					// find the machine object for this
					machines := MachinesForComputer(tx, object.SID())
					if len(machines) == 0 {
						ui.Warn().Msgf("Can not find machine object for DC %v", object.DN())
					}
					for _, machine := range machines {
						tx.Node(machine).Tag("role_domaincontroller")
						tx.Node(machine).Tag("hvt")

						domainContext := object.OneAttr(engine.DomainContext)
						if domainContext.IsNil() {
							ui.Fatal().Msgf("DomainController %v has no DomainContext attribute", object.DN())
						}

						if administrators, found := tx.FindTwo(engine.ObjectSid, engine.NV(windowssecurity.AdministratorsSID),
							engine.DomainContext, domainContext); found {
							tx.EdgeBecause(administrators, machine, activedirectory.EdgeLocalAdminRights, Inferred("a domain controller's local groups are the domain's built-in groups"))
						} else {
							ui.Warn().Msgf("Could not find Administrators group for %v", object.DN())
						}

						if remotedesktopusers, found := tx.FindTwo(engine.ObjectSid, engine.NV(windowssecurity.RemoteDesktopUsersSID),
							engine.DomainContext, domainContext); found {
							tx.EdgeBecause(remotedesktopusers, machine, activedirectory.EdgeLocalRDPRights, Inferred("a domain controller's local groups are the domain's built-in groups"))
						} else {
							ui.Warn().Msgf("Could not find Remote Desktop Users group for %v", object.DN())
						}

						if distributeddcomusers, found := tx.FindTwo(engine.ObjectSid, engine.NV(windowssecurity.DCOMUsersSID),
							engine.DomainContext, domainContext); found {
							tx.EdgeBecause(distributeddcomusers, machine, activedirectory.EdgeLocalDCOMRights, Inferred("a domain controller's local groups are the domain's built-in groups"))
						} else {
							ui.Warn().Msgf("Could not find DCOM Users group for %v", object.DN())
						}
					}
				}

				if object.HasAttrValue(activedirectory.PrimaryGroupID, engine.NV(521)) {
					// Read Only Domain Controller
					machines := MachinesForComputer(tx, object.SID())
					if len(machines) == 0 {
						ui.Warn().Msgf("Can not find machine object for RODC %v", object.DN())
					}
					for _, machine := range machines {
						tx.Node(machine).Tag("role_readonly_domaincontroller")
						tx.Node(machine).Tag("hvt")
					}

					// Figure out what hashes this machine has cached - FIXME!

				}
			}

			if object.Type() == engine.NodeTypeTrust {
				// http://www.frickelsoft.net/blog/?p=211
				var direction string
				dir, _ := object.AttrInt(activedirectory.TrustDirection)
				switch dir {
				case 0:
					direction = "disabled"
				case 1:
					direction = "incoming"
				case 2:
					direction = "outgoing"
				case 3:
					direction = "bidirectional"
				}

				attr, _ := object.AttrInt(activedirectory.TrustAttributes)

				partner := object.OneAttrString(activedirectory.TrustPartner)
				dnsroot := dnsRootOf[strings.ToLower(object.OneAttrString(engine.DomainContext))]

				ui.Info().Msgf("Domain %v has a %v trust with %v", dnsroot, direction, partner)

				if dir&2 != 0 && attr&0x08 != 0 && attr&0x40 != 0 {
					ui.Info().Msgf("SID filtering is not enabled, so pwn %v and pwn this AD too", object.OneAttr(activedirectory.TrustPartner))
				}

				TrustMap.Store(TrustPair{
					SourceDNSRoot: dnsroot,
					TargetDNSRoot: partner,
				}, TrustInfo{
					Direction: TrustDirection(dir),
				})
			}

			/* else if object.HasAttrValue(engine.ObjectClass, "classSchema") {
				if u, ok := object.OneAttrRaw(engine.SchemaIDGUID).(uuid.UUID); ok {
					// ui.Debug().Msgf("Adding schema class %v %v", u, object.OneAttr(Name))
					engine.AllSchemaClasses[u] = object
				}
			}*/
			return true
		})
	},
		engine.Processor{
			Description: "Active Directory objects and metadata",
			Phase:       engine.LoaderPhase,
			Needs:       []engine.Product{ProductNodeTypes, ProductDomainContext, ProductWellKnownPrincipals, ProductMachines},
			Provides:    []engine.Product{ProductAccountState, ProductMemberships},
		})

	LoaderID.AddProcessor(applyObjectClassAndCategoryPatches,
		engine.Processor{
			Description: "Set type (for Type call) to Active Directory objects",
			Phase:       engine.LoaderPhase,
			Provides:    []engine.Product{ProductNodeTypes},
		})

	LoaderID.AddProcessor(applyProtectedUserTags,
		engine.Processor{
			Description: "Protected users meta attribute",
			Phase:       engine.AnalysisPhase,
			Needs:       []engine.Product{ProductMemberships},
			Provides:    []engine.Product{ProductProtectedUsers},
		})

	// Loader.AddProcessor(func(ao *engine.Objects) {
	// 	// Find all the DomainDNS objects, and find the domain object
	// 	domains := make(map[string]windowssecurity.SID)

	// 	domaindnsobjects, found := tx.FindMulti(engine.ObjectClass, engine.NewAttributeValueString("domainDNS"))

	// 	if !found {
	// 		ui.Error().Msg("Could not find any domainDNS objects")
	// 	}

	// 	domaindnsobjects.Iterate(func(domaindnsobject *engine.Object) bool {
	// 		domainSID, sidok := domaindnsobject.OneAttrRaw(activedirectory.ObjectSid).(windowssecurity.SID)
	// 		dn := domaindnsobject.OneAttrString(activedirectory.DistinguishedName)
	// 		if sidok {
	// 			domains[dn] = domainSID
	// 		}
	// 		return true
	// 	})

	// 	tx.Iterate(func(o *engine.Object) bool {
	// 		if o.HasAttr(engine.ObjectSid) && o.SID().Component(2) == 21 && !o.HasAttr(engine.DistinguishedName) && o.HasAttr(engine.DomainContext) {
	// 			// An unknown SID, is it ours or from another domain?
	// 			ourDomainDN := o.OneAttrString(engine.DomainContext)
	// 			ourDomainSid, domainfound := domains[ourDomainDN]
	// 			if !domainfound {
	// 				return true
	// 			}

	// 			if o.SID().StripRID() == ourDomainSid {
	// 				// ui.Debug().Msgf("Found a 'dangling' local SID object %v. This is either a SID from a deleted object (most likely) or hardened objects that are not readable with the account used to dump data.", o.SID())
	// 			} else {
	// 				// ui.Debug().Msgf("Found a 'lost' foreign SID object %v, adding it as a synthetic Foreign-Security-Principal", o.SID())
	// 				o.SetFlex(
	// 					engine.DistinguishedName, engine.NewAttributeValueString(o.SID().String()+",CN=ForeignSecurityPrincipals,"+ourDomainDN),
	// 					engine.ObjectCategorySimple, "Foreign-Security-Principal",
	// 					engine.DataLoader, "Autogenerated",
	// 				)
	// 			}
	// 		}
	// 		return true
	// 	})
	// },
	// 	"Creation of synthetic Foreign-Security-Principal objects",
	// 	engine.AfterMergeLow)

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		addMachinesAffectedByGPO(tx)
	},
		engine.Processor{
			Description: "Machines affected by a GPO",
			Phase:       engine.AnalysisPhase,
			Needs:       []engine.Product{ProductMemberships, ProductMachines, ProductTree, ProductGPOStructure},
			Provides:    []engine.Product{ProductGPOTargeting},
		})

	LoaderID.AddProcessor(applyWellKnownSIDDisplayNames,
		engine.Processor{
			Description: "Adding displayName to Well-Known SID objects that are missing them",
			Phase:       engine.AnalysisPhase,
			Provides:    []engine.Product{ProductWellKnownDisplayNames},
		})

	// CREATOR_OWNER is a template for new objects, so this was totally wrong
	/*
		Loader.AddProcessor(func(ao *engine.Objects) {
			creatorowner, found := tx.Find(engine.ObjectSid, engine.AttributeValueSID(windowssecurity.CreatorOwnerSID))
			if !found {
				ui.Warn().Msg("Could not find Creator Owner Well Known SID. Not doing post-merge fixup")
				return
			}

			for target, edges := range creatorowner.CanPwn {
				// ACL grants CreatorOwnerSID something - so let's find the owner and give them the permissions
				if sd, err := target.SecurityDescriptor(); err == nil {
					if sd.Owner != windowssecurity.BlankSID {
						if realowners, found := tx.FindMulti(engine.ObjectSid, engine.AttributeValueSID(sd.Owner)); found {
							for _, realo := range realowners {
								if realo.Type() == engine.ObjectTypeForeignSecurityPrincipal || realo.Type() == engine.ObjectTypeOther {
									// Skip this
									continue
								}

								// Link real target
								realo.CanPwn[target] = realo.CanPwn[target].Merge(edges)
								target.PwnableBy[realo] = target.PwnableBy[realo].Merge(edges)

								// Unlink creatorowner
								delete(creatorowner.CanPwn, target)
								delete(target.PwnableBy, creatorowner)
							}
						}
					}
				}
			}
		},
			"CreatorOwnerSID resolution fixup",
			engine.BeforeMerge,
		)
	*/

	LoaderID.AddProcessor(func(tx *engine.Tx) {
		resolveMemberOfAndMember(tx)
	},
		engine.Processor{
			Description: "MemberOf and Member resolution",
			Phase:       engine.AnalysisPhase,
			Provides:    []engine.Product{ProductMemberships},
		})

	LoaderID.AddProcessor(applyIndirectMemberOfPatches,
		engine.Processor{
			Description: "MemberOfIndirect resolution",
			Phase:       engine.AnalysisPhase,
			Needs:       []engine.Product{ProductMemberships},
			Provides:    []engine.Product{ProductIndirectMemberships},
		})

	LoaderID.AddProcessor(addCertificateTemplatePublishing,
		engine.Processor{
			Description: "Certificate template publishing status",
			Phase:       engine.AnalysisPhase,
			Needs:       []engine.Product{ProductNodeTypes, ProductMachines},
			Provides:    []engine.Product{ProductCertificateTemplates},
		})

	LoaderID.AddProcessor(resolveGPOLocalGroupMembers,
		engine.Processor{
			Description: "Resolve GPO local group members given by name, expanding preference variables per machine",
			Phase:       engine.AnalysisPhase,
			Needs:       []engine.Product{ProductGPOTargeting},
			Provides:    []engine.Product{ProductGPOLocalGroups},
		})
}

// accountDisabled reports whether userAccountControl marks the account
// disabled. The KDC issues no service tickets for a disabled account.
func accountDisabled(o *engine.Node) bool {
	uac, ok := o.AttrInt(activedirectory.UserAccountControl)
	return ok && uac&engine.UAC_ACCOUNTDISABLE != 0
}

// addCertificateTemplatePublishing marks the templates enrollment services
// publish, the certificate authority machines, and the enrollment services
// publishing templates that are not found.
func addCertificateTemplatePublishing(tx *engine.Tx) {
	var missingTemplates int
	tx.Iterate(func(enrollementService *engine.Node) bool {
		if enrollementService.Type() == engine.NodeTypePKIEnrollmentService {
			if cadns := enrollementService.OneAttr(activedirectory.DNSHostName); !cadns.IsNil() {
				// find the CA machine object
				if ca, found := tx.FindTwo(
					engine.Type, ObjectTypeMachine.ValueString(),
					activedirectory.DNSHostName, cadns,
				); found {
					tx.Node(ca).Tag("role_certificate_authority")
					tx.Node(ca).Tag("hvt")
				} else {
					ui.Warn().Msgf("Couldn't locate dnsHostName %v acting as enrollmentservice", cadns)
				}
			}

			// Templates that is offered for enrollment
			var missing engine.AttributeValues
			enrollementService.Attr(CertificateTemplates).Iterate(func(templatename engine.AttributeValue) bool {

				templates, _ := tx.FindTwoMulti(engine.Name, templatename,
					engine.ObjectClass, engine.NV("pKICertificateTemplate"))

				alreadyset := false
				templates.Iterate(func(template *engine.Node) bool {
					if !engine.CompareAttributeValues(template.OneAttr(engine.DomainContext), enrollementService.OneAttr(engine.DomainContext)) {
						return true // continue
					}

					if alreadyset {
						ui.Warn().Msgf("Found multiple templates for %s", templatename)
					}

					tx.Node(template).SetFlex(PublishedBy, engine.NV(enrollementService.DN()),
						PublishedByDnsHostName, enrollementService.Attr(activedirectory.DNSHostName),
					)

					tx.Node(template).Tag("published")

					// classify the template as ESC1 - 11

					alreadyset = true
					return true
				})
				if !alreadyset {
					missing = append(missing, templatename)
				}
				return true
			})
			if len(missing) > 0 {
				missingTemplates += len(missing)
				tx.Node(enrollementService).Set(MissingCertificateTemplates, missing...).Tag(TagCertificateTemplateMissing)
			}
		}
		return true
	})
	if missingTemplates > 0 {
		ui.Info().Msgf("%v templates published by enrollment services are not found, tagged %v", missingTemplates, TagCertificateTemplateMissing)
	}
}
