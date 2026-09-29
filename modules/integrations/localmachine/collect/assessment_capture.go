package collect

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/lkarlslund/adalanche/modules/basedata"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

var errAssessmentLimit = errors.New("collection record or byte limit")

// Each category owns its bounded output. Failures never discard prior records.
type assessmentCapture struct {
	ctx   context.Context
	data  lm.AssessmentCapture
	bytes int
	limit int
	// budget is shared by categories running in parallel; the first
	// assessmentReserve bytes of each category are guaranteed instead.
	budget *assessmentBudget
}

func newAssessmentCapture(ctx context.Context) *assessmentCapture {
	return &assessmentCapture{ctx: ctx, limit: 8 << 20, data: lm.AssessmentCapture{
		Started: time.Now().UTC(), Scope: "local-machine",
		Result: basedata.CollectionResult{Status: basedata.CollectionCollected}, Records: []json.RawMessage{},
	}}
}

const (
	assessmentTotalLimit = 24 << 20
	assessmentReserve    = 128 << 10
)

// assessmentBudget bounds the combined size of categories captured in
// parallel. Each category keeps a small reserve so a large inventory cannot
// exhaust the budget before unrelated evidence is attempted.
type assessmentBudget struct {
	mu        sync.Mutex
	remaining int
}

func newAssessmentBudget(categories int) *assessmentBudget {
	return &assessmentBudget{remaining: max(0, assessmentTotalLimit-categories*assessmentReserve)}
}

func (b *assessmentBudget) take(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n > b.remaining {
		return false
	}
	b.remaining -= n
	return true
}

func (c *assessmentCapture) add(value any) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if len(c.data.Records) >= 10000 {
		return errAssessmentLimit
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw) > c.limit-c.bytes {
		return errAssessmentLimit
	}
	if c.budget != nil {
		shared := max(0, c.bytes+len(raw)-assessmentReserve) - max(0, c.bytes-assessmentReserve)
		if shared > 0 && !c.budget.take(shared) {
			return errAssessmentLimit
		}
	}
	c.bytes += len(raw)
	c.data.Records = append(c.data.Records, raw)
	return nil
}

func (c *assessmentCapture) failure(result basedata.CollectionResult) {
	if result.ErrorCode == "collection_limit" || result.Status == basedata.CollectionTimedOut {
		c.data.Truncated = true
	}
	if result.Status != basedata.CollectionCollected && c.data.Result.Status == basedata.CollectionCollected {
		c.data.Result = result
	}
}
