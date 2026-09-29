package analyze

import (
	"encoding/json"

	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/engine"
)

func retainPolicyResults(node *engine.Node, common basedata.Common, results basedata.CollectionResults) error {
	if len(results) == 0 {
		return nil
	} // Older data has unknown acquisition history.
	data, err := json.Marshal(struct {
		basedata.Common
		Results basedata.CollectionResults
	}{common, results})
	if err != nil {
		return err
	}
	node.SetFlex(GPOCollectionResults, string(data))
	return nil
}
