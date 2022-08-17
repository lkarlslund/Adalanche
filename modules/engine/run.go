package engine

import (
	"fmt"
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/ui"
)

// Loads, processes and merges everything. It's magic, just in code
func Run(path string) (*Objects, error) {
	var loaders []Loader

	for _, lg := range loadergenerators {
		loader := lg()

		ui.Debug().Msgf("Initializing loader for %v", loader.Name())
		err := loader.Init()
		if err != nil {
			return nil, err
		}
		loaders = append(loaders, loader)
	}

	// Load everything
	loadbar := ui.ProgressBar("Loading data", 0)

	lo, err := Load(loaders, path, func(cur, max int) {
		if max > 0 {
			loadbar.ChangeMax(max)
		} else if max < 0 {
			loadbar.ChangeMax(loadbar.GetMax() + (-max))
		}
		if cur > 0 {
			loadbar.Set(cur)
		} else {
			loadbar.Add(-cur)
		}
	})
	if err != nil {
		return nil, err
	}
	loadbar.Finish()

	var preprocessWG sync.WaitGroup
	for _, os := range lo {
		if os.Objects.Len() == 0 {
			// Don't bother with empty objects
			continue
		}

		preprocessWG.Add(1)
		go func(lobj loaderobjects) {
			lobj.Objects.SetThreadsafe(true)

			var loaderid LoaderID
			for i, loader := range loaders {
				if loader == lobj.Loader {
					loaderid = LoaderID(i)
					break
				}
			}

			pb := ui.ProgressBar(fmt.Sprintf("Preprocessing %v (low)", lobj.Loader.Name()), 0)
			Process(lobj.Objects, func(cur, max int) {
				if max > 0 {
					pb.ChangeMax(max)
				}
				if cur > 0 {
					pb.Set(cur)
				} else {
					pb.Add(-cur)
				}
			}, loaderid, BeforeMergeLow)
			pb.Finish()

			pb = ui.ProgressBar(fmt.Sprintf("Preprocessing %v (normal)", lobj.Loader.Name()), 0)
			Process(lobj.Objects, func(cur, max int) {
				if max > 0 {
					pb.ChangeMax(max)
				}
				if cur > 0 {
					pb.Set(cur)
				} else {
					pb.Add(-cur)
				}
			}, loaderid, BeforeMerge)
			pb.Finish()

			pb = ui.ProgressBar(fmt.Sprintf("Preprocessing %v (high)", lobj.Loader.Name()), 0)
			Process(lobj.Objects, func(cur, max int) {
				if max > 0 {
					pb.ChangeMax(max)
				}
				if cur > 0 {
					pb.Set(cur)
				} else {
					pb.Add(-cur)
				}
			}, loaderid, BeforeMergeHigh)
			pb.Finish()

			lobj.Objects.SetThreadsafe(false)

			preprocessWG.Done()
		}(os)
	}
	preprocessWG.Wait()

	// Analyze Pwn relationships
	var analyzeWG sync.WaitGroup
	for _, os := range lo {
		if os.Objects.Len() == 0 {
			// Don't bother with empty objects
			continue
		}

		analyzeWG.Add(1)
		func(lobj loaderobjects) {
			pwnbar := ui.ProgressBar(fmt.Sprintf("Analyzing %v objects from %v ...", lobj.Objects.Len(), lobj.Loader.Name()), 0)

			var loaderid LoaderID
			for i, loader := range loaders {
				if loader == lobj.Loader {
					loaderid = LoaderID(i)
					break
				}
			}

			loaderid.Analyze(lobj.Objects, func(cur, max int) {
				if max > 0 {
					pwnbar.ChangeMax(max)
				}
				if cur > 0 {
					pwnbar.Set(cur)
				} else {
					pwnbar.Add(-cur)
				}
			})

			pwnbar.Finish()
			analyzeWG.Done()
		}(os)
	}
	analyzeWG.Wait()

	// Merging
	objs := make([]*Objects, len(lo))
	for i, lobj := range lo {
		objs[i] = lobj.Objects
	}
	ao, err := Merge(objs)

	// Do global post-processing

	for i := range loaders {
		pb := ui.ProgressBar("Postprocessing merged objects (low)", 0)
		Process(ao, func(cur, max int) {
			if max > 0 {
				pb.ChangeMax(max)
			}
			if cur > 0 {
				pb.Set(cur)
			} else {
				pb.Add(-cur)
			}
		}, LoaderID(i), AfterMergeLow)
		pb.Finish()

		pb = ui.ProgressBar("Postprocessing merged objects (medium)", 0)
		Process(ao, func(cur, max int) {
			if max > 0 {
				pb.ChangeMax(max)
			}
			if cur > 0 {
				pb.Set(cur)
			} else {
				pb.Add(-cur)
			}
		}, LoaderID(i), AfterMerge)
		pb.Finish()

		pb = ui.ProgressBar("Postprocessing merged objects (high)", 0)
		Process(ao, func(cur, max int) {
			if max > 0 {
				pb.ChangeMax(max)
			}
			if cur > 0 {
				pb.Set(cur)
			} else {
				pb.Add(-cur)
			}
		}, LoaderID(i), AfterMergeHigh)
		pb.Finish()

		pb = ui.ProgressBar("Postprocessing merged objects (final)", 0)
		Process(ao, func(cur, max int) {
			if max > 0 {
				pb.ChangeMax(max)
			}
			if cur > 0 {
				pb.Set(cur)
			} else {
				pb.Add(-cur)
			}
		}, LoaderID(i), AfterMergeFinal)
		pb.Finish()
	}

	var statarray []string
	for stat, count := range ao.Statistics() {
		if stat == 0 {
			continue
		}
		if count == 0 {
			continue
		}
		statarray = append(statarray, fmt.Sprintf("%v: %v", ObjectType(stat).String(), count))
	}
	ui.Info().Msg(strings.Join(statarray, ", "))

	// Show debug counters
	var pwnarray []string
	for pwn, count := range EdgePopularity {
		if count == 0 {
			continue
		}
		pwnarray = append(pwnarray, fmt.Sprintf("%v: %v", Edge(pwn).String(), count))
	}
	ui.Debug().Msg(strings.Join(pwnarray, ", "))

	return ao, err
}
