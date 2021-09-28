package main

import (
	"math/bits"
	"sort"
)

// Enumer package from here:
// go get github.com/dmarkham/enumer

//go:generate enumer -type=PwnMethod -trimprefix=Pwn -json

// PwnAnalyzer takes an Object, examines it an outputs a list of Objects that can Pwn it
type PwnAnalyzer struct {
	Method         PwnMethod
	Description    string
	ObjectAnalyzer func(o *Object)
}

type PwnMethodBitmap uint64
type Probability uint8

type PwnInfo struct {
	Target      *Object
	Method      PwnMethod
	Probability Probability
}

type PwnMethod int

func (pm PwnMethodBitmap) Set(method PwnMethod) PwnMethodBitmap {
	pwnpopularity[method]++
	return pm | 1<<method
}

func (pm PwnMethodBitmap) Match(methods PwnMethodBitmap) PwnMethodBitmap {
	return pm & methods
}

func (pm PwnMethodBitmap) Methods() []PwnMethod {
	result := make([]PwnMethod, bits.OnesCount64(uint64(pm)))
	var n int
	for i := PwnMethod(1); i <= MaxPwnMethod; i++ {
		if pm.IsSet(i) {
			result[n] = i
			n++
		}
	}
	return result
}

func (pc PwnConnections) Objects() ObjectSlice {
	result := make(ObjectSlice, len(pc))
	var i int
	for object := range pc {
		result[i] = object
		i++
	}
	sort.Sort(result)
	return result
}

func (pc PwnConnections) Set(o *Object, method PwnMethod, probability Probability) {
	p := pc[o]
	pc[o] = p.Set(method)
}

/*
func (pmc *PwnMethodsAndProbabilities) Set(method PwnMethod, probability Probability) {
	pmc.PwnMethodBitmap = pmc.PwnMethodBitmap.Set(method)
	if probability != 100 {
		// find location for this
		var offset int
		for i := PwnMethod(1); i < method; i++ {
			if pmc.probabilitymap.IsSet(i) {
				offset++
			}
		}
		if !pmc.probabilitymap.IsSet(method) {
			// Insert
			newprobabilities := make(Probabilities, len(pmc.probabilities)+1)
			copy(newprobabilities, pmc.probabilities[:offset])
			copy(newprobabilities[offset+1:], pmc.probabilities[offset:])
			pmc.probabilities = newprobabilities
			pmc.probabilitymap = pmc.probabilitymap.Set(method)
		}
		pmc.probabilities[offset] = probability
	}
}

func (pmc *PwnMethodsAndProbabilities) GetProbability(method PwnMethod) Probability {
	if !pmc.IsSet(method) {
		return 0
	}
	if !pmc.probabilitymap.IsSet(method) {
		return 100
	}
	var offset int
	for i := PwnMethod(1); i < method; i++ {
		if pmc.probabilitymap.IsSet(i) {
			offset++
		}
	}
	return pmc.probabilities[offset]
}

func (pmc PwnMethodsAndProbabilities) GetMethodBitmap() PwnMethodBitmap {
	return pmc.PwnMethodBitmap
}*/

const (
	_ PwnMethod = iota
	PwnCreateUser
	PwnCreateGroup
	PwnCreateComputer
	PwnCreateAnyObject
	PwnDeleteChildrenTarget
	PwnDeleteObject
	PwnInheritsSecurity
	PwnACLContainsDeny
	PwnResetPassword
	PwnOwns
	PwnGenericAll
	PwnWriteAll
	PwnWritePropertyAll
	PwnWriteExtendedAll
	PwnTakeOwnership
	PwnWriteDACL
	PwnWriteSPN
	PwnWriteValidatedSPN
	PwnWriteAllowedToAct
	PwnAddMember
	PwnAddMemberGroupAttr
	PwnAddSelfMember
	PwnReadMSAPassword
	PwnHasMSA
	PwnWriteKeyCredentialLink
	PwnWriteAttributeSecurityGUID
	PwnSIDHistoryEquality
	PwnAllExtendedRights
	PwnDSReplicationSyncronize
	PwnDSReplicationGetChanges
	PwnDSReplicationGetChangesAll
	PwnDSReplicationGetChangesInFilteredSet
	PwnReadLAPSPassword
	PwnMemberOfGroup
	PwnHasSPN
	PwnHasSPNNoPreauth
	PwnAdminSDHolderOverwriteACL
	PwnComputerAffectedByGPO
	PwnGPOMachineConfigPartOfGPO
	PwnGPOUserConfigPartOfGPO
	PwnLocalAdminRights
	PwnLocalRDPRights
	PwnLocalDCOMRights
	PwnLocalSMSAdmins
	PwnLocalSessionLastDay
	PwnLocalSessionLastWeek
	PwnLocalSessionLastMonth
	PwnHasServiceAccountCredentials
	PwnHasAutoAdminLogonCredentials
	PwnScheduledTaskOnUNCPath
	PwnMachineScript
	PwnWriteAltSecurityIdentities
	PwnWriteProfilePath
	PwnWriteScriptPath
	PwnCertificateEnroll
	PwnRunsExecutable
	PwnHosts
	PwnRunsAs
	PwnExecuted
	MaxPwnMethod = iota - 1
)

var AllPwnMethods PwnMethodBitmap

var pwnpopularity [MaxPwnMethod + 1]uint64

func init() {
	for i := PwnMethod(1); i <= MaxPwnMethod; i++ {
		AllPwnMethods = AllPwnMethods.Set(i)
	}
}

/*
type PwnMethodsAndProbabilities struct {
	PwnMethodBitmap                 // Indicates if we have this method registered
	probabilitymap  PwnMethodBitmap // Indicates if we have a probability set or should just return 100
	probabilities   Probabilities
}
*/

type PwnConnections map[*Object]PwnMethodBitmap //sAndProbabilities

func (m PwnMethodBitmap) IsSet(method PwnMethod) bool {
	return (m & (1 << method)) != 0 // Uuuuh, nasty and unreadable
}

func (m PwnMethodBitmap) Intersect(methods PwnMethodBitmap) PwnMethodBitmap {
	return m & methods
}

func (m PwnMethodBitmap) Count() int {
	return bits.OnesCount64(uint64(m))
}

func (m PwnMethodBitmap) MaxProbabiltity(source, target *Object) Probability {
	var max Probability
	for i := PwnMethod(0); i <= MaxPwnMethod; i++ {
		if m.IsSet(i) {
			prob := CalculateProbability(source, target, PwnMethod(i))
			if prob == 100 {
				return prob
			}
			if prob > max {
				max = prob
			}
		}
	}
	return max
}

func (m PwnMethodBitmap) JoinedString() string {
	var result string
	for i := PwnMethod(1); i <= MaxPwnMethod; i++ {
		if m.IsSet(i) {
			if len(result) != 0 {
				result += ", "
			}
			result += i.String()
		}
	}
	return result
}

func (m PwnMethodBitmap) StringSlice() []string {
	var result []string
	for i := PwnMethod(1); i <= MaxPwnMethod; i++ {
		if m.IsSet(i) {
			result = append(result, i.String())
		}
	}
	return result
}

func (m PwnMethodBitmap) StringBoolMap() map[string]bool {
	var result = make(map[string]bool)
	for i := PwnMethod(1); i <= MaxPwnMethod; i++ {
		if m.IsSet(i) {
			result["pwn_"+i.String()] = true
		}
	}
	return result
}
