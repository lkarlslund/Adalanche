package ui

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/gookit/color"
	"github.com/pterm/pterm"
	"golang.org/x/term"
)

type progressBar struct {
	Started, Lastupdate time.Time

	writer io.Writer

	titleStyle    *pterm.Style
	barStyle      *pterm.Style
	Title         string
	ItemType      string
	barCharacter  string
	lastCharacter string
	barFiller     string

	Current, Total int64 // Absolute done and total
	RoundingFactor time.Duration

	lastReport int64

	Percent float32 // Percentage done
	ID      uuid.UUID
	Done    bool
}

var (
	pbLock       sync.Mutex
	progressbars = map[*progressBar]struct{}{}

	progressEnabled atomic.Bool
)

func init() {
	progressEnabled.Store(true)
}

type ProgressReport struct {
	StartTime      time.Time
	Title          string
	ItemType       string
	Current, Total int64
	Percent        float32
	ID             uuid.UUID
	Done           bool
}

func GetProgressReport() []ProgressReport {
	if !ProgressEnabled() {
		return nil
	}

	pbLock.Lock()
	pbr := make([]ProgressReport, len(progressbars))
	var i int
	for pb := range progressbars {
		if pb.Done && pb.lastReport == pb.Current {
			continue
		}
		pbr[i] = ProgressReport{
			ID:        pb.ID,
			Title:     pb.Title,
			ItemType:  pb.ItemType,
			Current:   pb.Current,
			Total:     pb.Total,
			Percent:   pb.Percent,
			Done:      pb.Done,
			StartTime: pb.Started,
		}
		pb.lastReport = pb.Current
		i++
	}
	pbLock.Unlock()
	return pbr[:i]
}

func SetProgressEnabled(enabled bool) {
	progressEnabled.Store(enabled)
}

func ProgressEnabled() bool {
	return progressEnabled.Load()
}

func ProgressBar(title string, max int64) *progressBar {
	if max == 0 {
		max = 1 // avoid division by zero in pterm
	}

	id, _ := uuid.NewV7()
	pb := progressBar{
		ID:    id,
		Title: title,

		Total:          int64(max),
		RoundingFactor: time.Second,
		barCharacter:   "█",
		lastCharacter:  "█",
		barFiller:      " ",
	}
	if pb.titleStyle == nil {
		pb.titleStyle = pterm.NewStyle()
	}
	if pb.barStyle == nil {
		pb.barStyle = pterm.NewStyle()
	}

	pb.Start()

	// Save it
	if ProgressEnabled() {
		pbLock.Lock()
		progressbars[&pb] = struct{}{}
		pbLock.Unlock()
	}

	return &pb
}

func (pb *progressBar) ChangeMax(newmax int64) {
	if newmax == 0 {
		Fatal().Msg("Cannot set max to 0")
	}
	pb.Total = int64(newmax)
}

func (pb *progressBar) GetMax() int64 {
	return pb.Total
}

func (pb *progressBar) Start() {
	pb.Started = time.Now()
}

func (pb *progressBar) Add(i int64) {
	atomic.AddInt64(&pb.Current, i)
	pb.update()
}

func (pb *progressBar) Set(i int64) {
	atomic.StoreInt64(&pb.Current, i)
	pb.update()
}

func (pb *progressBar) SetTitle(title string) {
	pb.Title = title
}

func (pb *progressBar) Finish() {
	if !ProgressEnabled() {
		pb.Done = true
		return
	}

	// Save it
	pbLock.Lock()
	delete(progressbars, pb)
	pbLock.Unlock()

	pb.Done = true

	// A finished bar leaves nothing behind on the terminal.
	outputMutex.Lock()
	clearProgressLine(pb.writer)
	outputMutex.Unlock()
}

// stdoutIsTerminal says whether bars are drawn: in a log written to a file
// or pipe they would only repeat lines.
var stdoutIsTerminal = term.IsTerminal(int(os.Stdout.Fd()))

func (pb *progressBar) update() {
	if !ProgressEnabled() {
		return
	}
	var currentPercentage float32
	if total := atomic.LoadInt64(&pb.Total); total > 0 {
		currentPercentage = float32(atomic.LoadInt64(&pb.Current)) * 100 / float32(total)
	}
	if currentPercentage > 100 {
		currentPercentage = 100
	}
	// The web UI reads the percentage, so it is kept current even when the
	// bar is not drawn.
	pb.Percent = currentPercentage

	if (pb.writer == nil && !stdoutIsTerminal) || time.Since(pb.Lastupdate) < 1*time.Second {
		return
	}

	outputMutex.Lock()

	clearneeded = true
	pb.Lastupdate = time.Now()

	var before string
	var after string

	width := pterm.GetTerminalWidth()

	decoratorCount := pterm.Gray("[") + pterm.LightWhite(pb.Current) + pterm.Gray("/") + pterm.LightWhite(pb.Total) + pterm.Gray("]")

	decoratorCurrentPercentage := color.RGB(pterm.NewRGB(255, 0, 0).Fade(0, float32(pb.Total), float32(pb.Current), pterm.NewRGB(0, 255, 0)).GetValues()).
		Sprint(fmt.Sprintf("%.2f%%", currentPercentage))

	decoratorTitle := pb.titleStyle.Sprint(pb.Title)

	before += decoratorTitle + " "
	before += decoratorCount + " "

	after += " "

	after += decoratorCurrentPercentage + " "
	after += "| " + time.Since(pb.Started).Round(pb.RoundingFactor).String()

	barMaxLength := width - len(pterm.RemoveColorFromString(before)) - len(pterm.RemoveColorFromString(after)) - 1

	barCurrentLength := int(math.Round(float64(currentPercentage * float32(barMaxLength) / 100)))

	var barFiller string
	if barMaxLength-barCurrentLength > 0 {
		barFiller = strings.Repeat(pb.barFiller, barMaxLength-barCurrentLength)
	}

	var bar string
	if pb.Total > 0 && barCurrentLength > 0 {
		bar = pb.barStyle.Sprint(strings.Repeat(pb.barCharacter, barCurrentLength)+pb.lastCharacter) + barFiller
	} else {
		bar = ""
	}

	pterm.Fprinto(pb.writer, before+bar+after)

	outputMutex.Unlock()
}
