package collect

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/adalanche/modules/basedata"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/spf13/cobra"
)

var assessmentOnly, assessmentSkip []string
var assessmentCategories = []string{"smb-client", "smb-server", "credential-protection", "lsa-protection-runtime", "service-runtime", "task-security", "listeners", "firewall-profiles", "network-profiles", "firewall-rules", "remote-endpoints", "remote-listeners", "startup", "event-subscriptions", "event-consumers", "machine-certificates", "credential-locations", "password-management-policy", "password-management-events", "user-installer-policy", "policy-provenance", "service-payloads", "task-payloads", "firewall-filters", "remote-configuration", "wmi-security", "dcom-security", "current-sessions", "process-identities", "authentication-policy", "smb-shares", "smb-connections"}
var assessmentSummary = true
var assessmentExtraCategories = []string{"path-security", "service-restrictions"}

// RegisterAssessmentCategories adds category names to CLI validation.
// Categories of registered collectors are added automatically.
// Call during initialization, before command execution.
func RegisterAssessmentCategories(names ...string) {
	assessmentExtraCategories = append(assessmentExtraCategories, names...)
}

func init() {
	Cmd.Flags().StringSliceVar(&assessmentOnly, "assessment-only", nil, "Only these assessment categories (comma-separated); base inventory is unchanged")
	Cmd.Flags().StringSliceVar(&assessmentSkip, "assessment-skip", nil, "Skip these assessment categories (comma-separated)")
	Cmd.Flags().BoolVar(&assessmentSummary, "assessment-summary", true, "Print assessment coverage counts and category timings")
	Cmd.Flags().IntVar(&collectWorkers, "workers", 0, "Collection jobs run at once (0 = a quarter of the logical processors, at least one)")
	Cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if collectWorkers < 0 {
			return fmt.Errorf("--workers must not be negative")
		}
		known := slices.Concat(assessmentCategories, assessmentExtraCategories, registeredCategories())
		slices.Sort(known)
		return validateAssessmentSelection(assessmentOnly, assessmentSkip, slices.Compact(known))
	}
}

func validateAssessmentSelection(only, skip, known []string) error {
	for _, names := range [][]string{only, skip} {
		for _, name := range names {
			if !slices.Contains(known, name) {
				slices.Sort(known)
				return fmt.Errorf("unknown assessment category %q; available: %s", name, strings.Join(known, ","))
			}
		}
	}
	for _, name := range only {
		if slices.Contains(skip, name) {
			return fmt.Errorf("assessment category %q is both selected and skipped", name)
		}
	}
	return nil
}

// AssessmentEnabled applies the shared CLI selection to core and extension collectors.
func AssessmentEnabled(name string) bool {
	return (len(assessmentOnly) == 0 || slices.Contains(assessmentOnly, name)) && !slices.Contains(assessmentSkip, name)
}

// WriteAssessmentSummary emits category names, counts and outcomes only, not identities.
func WriteAssessmentSummary(w io.Writer, info *lm.Info) {
	if !assessmentSummary {
		return
	}
	writeCollectionJobSummary(w, info)
	a, err := lm.DecodeAssessment(info.AssessmentData)
	if err != nil {
		fmt.Fprintln(w, "Assessment summary unavailable")
		return
	}
	names := make([]string, 0, len(a.Categories))
	counts := map[basedata.CollectionStatus]int{}
	truncated := 0
	for name, category := range a.Categories {
		names = append(names, name)
		counts[category.Result.Status]++
		if category.Truncated {
			truncated++
		}
	}
	slices.Sort(names)
	fmt.Fprintf(w, "Assessment: %d categories; collected=%d denied=%d unsupported=%d absent=%d failed=%d timed_out=%d canceled=%d skipped=%d truncated=%d\n", len(names), counts[basedata.CollectionCollected], counts[basedata.CollectionAccessDenied], counts[basedata.CollectionUnsupported], counts[basedata.CollectionNotFound], counts[basedata.CollectionFailed], counts[basedata.CollectionTimedOut], counts[basedata.CollectionCanceled], counts[basedata.CollectionNotRequested], truncated)
	for _, name := range names {
		category := a.Categories[name]
		if category.Result.Status == basedata.CollectionNotRequested {
			continue
		}
		elapsed := time.Duration(0)
		if !category.Started.IsZero() && !category.Completed.Before(category.Started) {
			elapsed = category.Completed.Sub(category.Started).Round(time.Millisecond)
		}
		count := len(category.Records)
		if name == "path-security" {
			count = len(a.Paths)
		}
		suffix := ""
		if category.Truncated {
			suffix = " truncated"
		}
		if code := category.Result.ErrorCode; code != "" {
			suffix += " " + code // Machine-readable only, never error text.
		}
		fmt.Fprintf(w, "  %-30s %-15s %5d records %9s%s\n", name, category.Result.Status, count, elapsed, suffix)
	}
}

// Report collection jobs that failed or were abandoned; their data is missing.
func writeCollectionJobSummary(w io.Writer, info *lm.Info) {
	var incomplete []string
	jobs := 0
	for key, result := range info.CollectionResults {
		name, ok := strings.CutPrefix(key, collectJobOutcomePrefix)
		if !ok {
			continue
		}
		jobs++
		if result.Status != basedata.CollectionCollected {
			incomplete = append(incomplete, strings.TrimSpace(fmt.Sprintf("%s=%s %s", name, result.Status, result.ErrorCode)))
		}
	}
	slices.Sort(incomplete)
	fmt.Fprintf(w, "Collection: %d jobs with %d workers; incomplete=%d\n", jobs, effectiveCollectWorkers(), len(incomplete))
	for _, job := range incomplete {
		fmt.Fprintf(w, "  %s\n", job)
	}
}
