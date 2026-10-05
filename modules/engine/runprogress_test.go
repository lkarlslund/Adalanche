package engine

import "testing"

type recordingBar struct {
	value int64
	title string
	done  bool
}

func (b *recordingBar) Set(v int64)       { b.value = v }
func (b *recordingBar) SetTitle(t string) { b.title = t }
func (b *recordingBar) Finish()           { b.done = true }

// Each stage covers its share of the one bar, after the stages before it.
func TestRunProgressStages(t *testing.T) {
	bar := &recordingBar{}
	p := &runProgress{bar: bar}
	p.stage("Loading files", 300)
	p.within(1, 2)
	if bar.value != 150 || bar.title != "Loading files" {
		t.Fatalf("half way through loading: %v %q", bar.value, bar.title)
	}
	p.stage("Processors", 200)
	if bar.value != 300 {
		t.Fatalf("start of the second stage: %v", bar.value)
	}
	p.within(5, 4) // over-reporting stays within the stage
	if bar.value != 500 {
		t.Fatalf("end of the second stage: %v", bar.value)
	}
	p.within(1, 0) // no total yet: no change
	if bar.value != 500 {
		t.Fatalf("without a total: %v", bar.value)
	}
	p.finish()
	if bar.value != runProgressTotal || !bar.done {
		t.Fatalf("finished: %v %v", bar.value, bar.done)
	}
}
