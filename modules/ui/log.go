package ui

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mattn/go-colorable"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

//go:generate go tool github.com/dmarkham/enumer -trimprefix=Level -type=LogLevel -output loglevel_enums.go

func init() {
	zlog.Logger = zlog.Output(zerolog.ConsoleWriter{
		Out:        colorable.NewColorableStdout(),
		TimeFormat: "15:04:05.000",
	})
	pterm.PrintDebugMessages = true
}

type LogLevel int

const (
	LevelTrace LogLevel = iota
	LevelDebug
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
	LevelPanic
)

var (
	logLevel    = LevelInfo
	clearneeded bool

	Zerotime  bool
	starttime = time.Now()
)

func SetLoglevel(i LogLevel) {
	logLevel = i
}

func GetLoglevel() LogLevel {
	return logLevel
}

var logfile *os.File
var logfileinit bool // Should we stop buffering output?
var logfilebuffer *bytes.Buffer
var logfilelevel LogLevel = LevelInfo

func SetLogFile(path string, i LogLevel) error {
	outputMutex.Lock()
	defer outputMutex.Unlock()

	logfileinit = true

	if logfile != nil {
		logfile.Close()
		logfile = nil
	}

	if path == "" {
		logfilebuffer = nil
		return nil
	}

	// Ensure path exists
	os.MkdirAll(filepath.Dir(path), 0660)

	var err error
	logfile, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open logfile %s: %s", path, err)
	}

	logfilelevel = i

	if logfilebuffer != nil && logfilebuffer.Available() > 0 {
		io.Copy(logfile, logfilebuffer)
		logfilebuffer = nil
	}

	return nil
}

type Logger struct {
	ll     LogLevel
	output *zerolog.Event
	pterm  pterm.PrefixPrinter
}

func (t Logger) Msgf(format string, args ...any) {
	if logLevel > t.ll && (logfileinit && logfilelevel > t.ll) {
		return
	}

	outputMutex.Lock()

	var timetext string
	if Zerotime {
		elapsed := time.Since(starttime)
		timetext = fmt.Sprintf("%02d:%02d:%02d.%03d", int(elapsed.Hours()), int(elapsed.Minutes())%60, int(elapsed.Seconds())%60, elapsed.Milliseconds()%1000)
	} else {
		timetext = time.Now().Format("15:04:05.000")
	}

	if logfileinit {
		if logfile != nil && logfilelevel <= t.ll {
			fmt.Fprintf(logfile, timetext+" "+t.ll.String()+" "+format+"\n", args...)
		}
	} else {
		if logLevel <= t.ll { // use console output loglevel
			if logfilebuffer == nil {
				logfilebuffer = bytes.NewBuffer(nil)
			}
			logfilebuffer.WriteString(fmt.Sprintf(timetext+" "+t.ll.String()+" "+format+"\n", args...))
		}
	}
	if logLevel <= t.ll {
		if clearneeded {
			pterm.Fprinto(t.pterm.Writer, strings.Repeat(" ", pterm.GetTerminalWidth()))
			pterm.Fprinto(t.pterm.Writer)
			clearneeded = false
		}

		tprefix := pterm.DefaultBasicText.Sprint(timetext + " ")
		pterm.Fprint(t.pterm.Writer, tprefix+t.pterm.Sprintfln(format, args...))
	}
	if t.ll == LevelFatal {
		if logfile != nil {
			logfile.Close()
		}
		os.Exit(1)
	}
	outputMutex.Unlock()
	if t.ll == LevelPanic {
		panic(fmt.Sprintf(format, args...))
	}
}

func (t Logger) Msg(msg string) Logger {
	t.Msgf(msg)
	return t
}

func (t Logger) Err(e error) Logger {
	if logLevel <= t.ll {
		t.Msgf("Error: %v", e.Error())
	}
	return t
}

func Debug() Logger {
	return Logger{
		LevelDebug,
		zlog.Debug(),
		pterm.Debug,
	}
}

func Warn() Logger {
	return Logger{
		LevelWarn,
		zlog.Warn(),
		pterm.PrefixPrinter{
			MessageStyle: &pterm.ThemeDefault.WarningMessageStyle,
			Prefix: pterm.Prefix{
				Style: &pterm.ThemeDefault.WarningPrefixStyle,
				Text:  "WARNING",
			},
		},
	}
}

func Error() Logger {
	return Logger{
		LevelError,
		zlog.Error(),
		pterm.Error,
	}
}

func Fatal() Logger {
	return Logger{
		LevelFatal,
		zlog.Fatal(),
		pterm.Fatal,
	}
}

func Info() Logger {
	return Logger{
		LevelInfo,
		zlog.Info(),
		pterm.PrefixPrinter{
			MessageStyle: &pterm.ThemeDefault.InfoMessageStyle,
			Prefix: pterm.Prefix{
				Style: &pterm.ThemeDefault.InfoPrefixStyle,
				Text:  "INFORMA",
			},
		},
	}
}

func Trace() Logger {
	return Logger{
		LevelTrace,
		zlog.Trace(),
		pterm.PrefixPrinter{
			MessageStyle: &pterm.ThemeDefault.InfoMessageStyle,
			Prefix: pterm.Prefix{
				Style: &pterm.Style{pterm.FgCyan},
				Text:  "TRACE",
			},
		},
	}
}
