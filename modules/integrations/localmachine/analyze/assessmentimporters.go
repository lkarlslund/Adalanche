package analyze

import (
	"sync"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

// AssessmentImporter extracts what analysis needs from a machine's assessment
// while it is decoded during import; the assessment itself is not kept.
type AssessmentImporter func(*engine.Tx, engine.TxNode, *localmachine.Assessment) error

var (
	assessmentImportersLock sync.RWMutex
	assessmentImporters     []AssessmentImporter
)

// RegisterAssessmentImporter adds an importer that runs for every machine
// collection with an assessment. It may be invoked concurrently for
// independent machine collections.
func RegisterAssessmentImporter(importer AssessmentImporter) {
	assessmentImportersLock.Lock()
	assessmentImporters = append(assessmentImporters, importer)
	assessmentImportersLock.Unlock()
}

func importAssessment(tx *engine.Tx, machine engine.TxNode, assessment *localmachine.Assessment) error {
	importAssessmentPolicyProvenance(tx, machine, assessment)
	assessmentImportersLock.RLock()
	defer assessmentImportersLock.RUnlock()
	for _, importer := range assessmentImporters {
		if err := importer(tx, machine, assessment); err != nil {
			return err
		}
	}
	return nil
}
