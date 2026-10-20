package collect

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"

	smb2 "github.com/cloudsoda/go-smb2"
	clicollect "github.com/lkarlslund/adalanche/modules/cli/collect"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
)

// errPolicyAborted marks a GPO that was not collected because another GPO
// failed first.
var errPolicyAborted = errors.New("aborted after another policy failed")

// policyJob is one GPO whose files should be collected into output.
type policyJob struct {
	info   activedirectory.GPOdump
	local  string // local or mounted path, used when not collecting over SMB
	share  string // SMB share and share-relative path, used with SMB
	rel    string
	output string
	legacy bool // write the legacy JSON format instead of a v2 collection
}

// policyCollector collects GPO files with a pool of workers. With an SMB
// initiator each worker uses its own SMB session to smbServer.
type policyCollector struct {
	workers      int
	smbServer    string
	smbInitiator func() smb2.Initiator
}

// run collects all jobs and returns one error per job, in job order. After the
// first failure the remaining jobs are cancelled and report errPolicyAborted.
func (pc policyCollector) run(ctx context.Context, jobs []policyJob) []error {
	errs := make([]error, len(jobs))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	workers := min(max(pc.workers, 1), len(jobs))
	if pc.smbInitiator != nil && len(jobs) > 0 {
		ui.Info().Msgf(`Collecting group policy files over SMB from \\%v\%v using %v sessions`, pc.smbServer, jobs[0].share, workers)
	}

	var failed sync.Once
	next := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			clients := map[string]*smbPolicyClient{}
			defer func() {
				for _, c := range clients {
					c.Close()
				}
			}()
			for i := range next {
				if ctx.Err() != nil {
					errs[i] = errPolicyAborted
					continue
				}
				err := pc.collect(ctx, jobs[i], clients)
				if err != nil {
					aborted := true
					failed.Do(func() {
						aborted = false
						cancel()
					})
					if aborted {
						err = errPolicyAborted
					}
				}
				errs[i] = err
			}
		})
	}
	for i := range jobs {
		next <- i
	}
	close(next)
	wg.Wait()
	return errs
}

func (pc policyCollector) collect(ctx context.Context, job policyJob, clients map[string]*smbPolicyClient) error {
	var src policySource
	if pc.smbInitiator != nil {
		client := clients[job.share]
		if client == nil {
			var err error
			client, err = newSMBPolicyClient(ctx, pc.smbServer, job.share, pc.smbInitiator())
			if err != nil {
				return err
			}
			clients[job.share] = client
		}
		ui.Info().Msgf("Collecting group policy files from %v ...", job.info.Path)
		src = client.source(job.rel)
	} else {
		ui.Info().Msgf("Collecting group policy files from %v ...", job.local)
		src = localPolicySource{info: job.info, root: job.local}
	}

	if !job.legacy {
		return writePolicyFiles(ctx, job.output, job.info, src)
	}
	data, err := json.MarshalIndent(collectPolicyFiles(job.info, src), "", "  ")
	if err != nil {
		return err
	}
	return clicollect.WriteFileAtomic(job.output, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}
