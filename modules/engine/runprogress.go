package engine

import (
	"github.com/lkarlslund/adalanche/modules/ui"
)

// runProgress is the one progress bar of an analysis run. The run moves
// through stages, each taking a share of the bar roughly in proportion to
// its usual duration, and each stage reports how far it is within itself.
type runProgress struct {
	bar interface {
		Set(int64)
		SetTitle(string)
		Finish()
	}
	start, share int64 // the current stage's part of the bar
}

const runProgressTotal = 1000

// Stage shares of the bar, in thousandths, from measured full runs.
const (
	shareLoading          = 350
	shareLoaderProcessors = 70
	shareFinishingLoading = 120
	shareAnalysis         = 360
	shareGraphAttributes  = 100
)

func newRunProgress() *runProgress {
	return &runProgress{bar: ui.ProgressBar("Analysis", runProgressTotal)}
}

// stage moves on to the next stage, named title, taking share of the bar.
func (p *runProgress) stage(title string, share int64) {
	p.start += p.share
	p.share = share
	p.bar.SetTitle(title)
	p.bar.Set(p.start)
}

// within reports how far the current stage is.
func (p *runProgress) within(done, total int) {
	if total <= 0 {
		return
	}
	done = min(max(done, 0), total)
	p.bar.Set(p.start + p.share*int64(done)/int64(total))
}

func (p *runProgress) finish() {
	p.bar.Set(runProgressTotal)
	p.bar.Finish()
}
