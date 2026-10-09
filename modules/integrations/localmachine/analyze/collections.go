package analyze

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/attrs"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

// Tags on machine collections that claim the same computer account.
const (
	TagComputerAccountShared = "computer_account_shared" // another collection claims the same account
	TagCollectionCurrent     = "collection_current"      // the newest of those collections
	TagCollectionSuperseded  = "collection_superseded"   // an older collection of the same machine (same firmware UUID)
	TagCollectionClone       = "collection_clone"        // a different machine with the same account (different firmware UUID)
	TagCollectionUnresolved  = "collection_superseded_or_clone"
)

func init() {
	engine.RegisterMergePreparer(chooseCurrentCollections)
}

func isMachineCollection(n *engine.Node) bool {
	return n.HasAttr(localmachine.CollectedSettings)
}

type claim struct {
	graph *engine.IndexedGraph
	node  *engine.Node
	at    time.Time
	uuid  string
}

// chooseCurrentCollections picks, for every computer account claimed by
// machine collections, the newest collection as the one that merges with the
// account's machine from the directory. When several collections claim an
// account, all are kept and tagged; the firmware UUID tells a later
// collection of the same machine from a clone when both have it.
func chooseCurrentCollections(graphs []*engine.IndexedGraph) error {
	claims := map[string][]claim{}
	for _, g := range graphs {
		g.Iterate(func(n *engine.Node) bool {
			if !isMachineCollection(n) {
				return true
			}
			sid := n.OneAttr(attrs.DomainJoinedSID)
			if sid.IsNil() {
				return true
			}
			at, _ := n.AttrTime(localmachine.CollectedAt)
			claims[sid.String()] = append(claims[sid.String()], claim{g, n, at, strings.ToUpper(n.OneAttrString(localmachine.SMBIOSUUID))})
			return true
		})
	}

	type write func(tx *engine.Tx)
	writes := map[*engine.IndexedGraph][]write{}
	for _, group := range claims {
		// Newest first; the rest of the order only has to be the same on
		// every run.
		slices.SortFunc(group, func(a, b claim) int {
			return cmp.Or(b.at.Compare(a.at), strings.Compare(a.uuid, b.uuid),
				strings.Compare(a.node.OneAttrString(localmachine.CollectedSettings), b.node.OneAttrString(localmachine.CollectedSettings)))
		})
		current := group[0]
		sid := current.node.OneAttr(attrs.DomainJoinedSID)
		writes[current.graph] = append(writes[current.graph], func(tx *engine.Tx) {
			h := tx.Node(current.node).Set(attrs.PrimaryMachineFor, sid)
			if len(group) > 1 {
				h.Tag(TagComputerAccountShared).Tag(TagCollectionCurrent)
			}
		})
		for _, other := range group[1:] {
			tag := TagCollectionUnresolved
			if other.uuid != "" && current.uuid != "" {
				tag = TagCollectionClone
				if other.uuid == current.uuid {
					tag = TagCollectionSuperseded
				}
			}
			writes[other.graph] = append(writes[other.graph], func(tx *engine.Tx) {
				tx.Node(other.node).Tag(TagComputerAccountShared).Tag(tag)
			})
		}
	}
	for g, ws := range writes {
		tx := g.Begin("choose current machine collections")
		for _, w := range ws {
			w(tx)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
