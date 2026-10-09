package analyze

import (
	"errors"
	"strconv"
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
)

// Configuration findings: references in the directory to objects that do not
// exist. They create no attack paths, but they are stale configuration a
// defender can clean up, so the objects holding them are tagged, and the
// missing items are kept on the object.
var (
	BrokenGPLinks               = engine.NewAttribute("brokenGPLinks")
	MissingDelegationTargets    = engine.NewAttribute("missingDelegationTargets")
	MissingCertificateTemplates = engine.NewAttribute("missingCertificateTemplates")
)

const (
	TagGPOLinkBroken              = "gpo_link_broken"
	TagDelegationTargetMissing    = "delegation_target_missing"
	TagCertificateTemplateMissing = "certificate_template_missing"
)

func init() {
	LoaderID.AddProcessor(tagBrokenGPOLinks, engine.Processor{
		Description: "Containers linking to GPOs that are not found",
		Phase:       engine.AnalysisPhase,
		Provides:    []engine.Product{ProductConfigurationFindings},
	})
}

type gpLinkEntry struct {
	dn      string
	options int64
}

var errGPLinkSyntax = errors.New("gPLink syntax")

// parseGPLink splits a gPLink value into its GPO links (MS-GPOL 2.2.2):
// [LDAP://<GPO DN>;<options>] repeated.
func parseGPLink(value string) ([]gpLinkEntry, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return nil, errGPLinkSyntax
	}
	var links []gpLinkEntry
	var err error
	for link := range strings.SplitSeq(value[1:len(value)-1], "][") {
		path, options, found := strings.Cut(link, ";")
		if !found || len(path) < 7 || !strings.EqualFold(path[:7], "LDAP://") {
			err = errGPLinkSyntax
			continue
		}
		parsed, _ := strconv.ParseInt(options, 10, 64)
		links = append(links, gpLinkEntry{dn: path[7:], options: parsed})
	}
	return links, err
}

// tagBrokenGPOLinks tags containers whose gPLink names GPOs that exist
// neither in the directory nor in SYSVOL.
func tagBrokenGPOLinks(tx *engine.Tx) {
	var containers int
	missing := make(map[string]struct{})
	tx.Iterate(func(som *engine.Node) bool {
		gplink := som.OneAttrString(activedirectory.GPLink)
		if gplink == "" {
			return true
		}
		links, err := parseGPLink(gplink)
		if err != nil {
			ui.Error().Msgf("Error parsing gPLink on %v: %v", som.DN(), gplink)
		}
		var broken engine.AttributeValues
		for _, link := range links {
			if _, found := tx.FindMulti(engine.DistinguishedName, engine.NV(link.dn)); !found {
				broken = append(broken, engine.NV(link.dn))
				missing[strings.ToLower(link.dn)] = struct{}{}
			}
		}
		if len(broken) > 0 {
			containers++
			tx.Node(som).Set(BrokenGPLinks, broken...).Tag(TagGPOLinkBroken)
		}
		return true
	})
	if containers > 0 {
		ui.Info().Msgf("%v objects link to %v GPOs that are not found, tagged %v", containers, len(missing), TagGPOLinkBroken)
	}
}
