package settings

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// Status says where a configuration came from and what was said about the
// settings.
type Status struct {
	// Source is "file", or where the settings were read from ("appconfig").
	Source string
	// Applied is how many settings were taken.
	Applied int
	// Warnings names the settings that were not, and why.
	Warnings []string
	// Error says why the settings were not used at all.
	Error    string
	LoadedAt time.Time
}

// ReadFile reads a configuration file. A file that does not exist is not an
// error when the settings can supply everything (optional).
func ReadFile(path string, optional bool) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && optional {
		return nil, nil
	}
	return b, err
}

// Loader reads one tool's configuration: its file with the settings laid
// over it.
type Loader[C any] struct {
	Spec Spec
	// File is the configuration file's JSON; empty when there is none.
	File []byte
	// Fetch reads the settings. Nil runs on the file alone.
	Fetch Fetch
	// Source names where Fetch reads from (default "appconfig").
	Source string
	// Parse validates configuration JSON, as the tool always did.
	Parse func([]byte) (C, error)

	// loaded: a configuration has been returned before.
	loaded bool
}

// Load reads the settings and lays them over the file. It is called before
// every pass, so that a change in App Configuration applies to the next
// one.
//
// When the settings cannot be read, or the result is not a valid
// configuration, the first call falls back to the file alone and says why
// in the status. A later call returns an error instead, for the caller to
// go on with the configuration it has: a store that is out of reach for a
// moment must not take away what only the settings define.
func (l *Loader[C]) Load(ctx context.Context) (C, Status, error) {
	cfg, status, err := l.load(ctx)
	if err == nil {
		l.loaded = true
	}
	return cfg, status, err
}

func (l *Loader[C]) load(ctx context.Context) (C, Status, error) {
	var zero C
	status := Status{Source: "file", LoadedAt: time.Now().UTC()}
	// cause is why the settings were not used.
	var cause error
	if l.Fetch != nil {
		source := l.Source
		if source == "" {
			source = "appconfig"
		}
		s, extra, err := l.Fetch(ctx)
		if err != nil {
			status.Error = "the settings could not be read: " + err.Error()
			cause = errors.New(status.Error)
		} else {
			res, err := Merge(l.File, s, l.Spec)
			if err == nil {
				cfg, perr := l.Parse(res.Config)
				if perr == nil {
					status.Source, status.Applied = source, res.Applied
					status.Warnings = append(append(status.Warnings, extra...), res.Warnings...)
					return cfg, status, nil
				}
				err = perr
			}
			status.Warnings = append(status.Warnings, extra...)
			cause = fmt.Errorf("the settings under %s were not used: %w", Key(l.Spec.Tool), err)
			status.Error = "the settings were not used, the configuration file is: " + err.Error()
			if l.loaded {
				status.Error = cause.Error()
			}
		}
		if l.loaded {
			return zero, status, cause
		}
	}
	if len(strings.TrimSpace(string(l.File))) == 0 {
		if cause != nil {
			return zero, status, fmt.Errorf("%w (and there is no configuration file to fall back to)", cause)
		}
		return zero, status, errors.New("no configuration: give a configuration file, or settings under " + Key(l.Spec.Tool) + " in App Configuration")
	}
	cfg, err := l.Parse(l.File)
	if err != nil {
		if status.Error != "" {
			// Both failed: say why the settings did not help either.
			return zero, status, fmt.Errorf("%w (%s)", err, status.Error)
		}
		return zero, status, err
	}
	return cfg, status, nil
}

// Reporter logs what the settings did once, and again when it changes.
type Reporter struct{ last string }

// NotReloaded logs that the configuration could not be read again and that
// the one loaded before stays in use: once, and again when the reason
// changes.
func (r *Reporter) NotReloaded(log *slog.Logger, err error) {
	summary := "not reloaded|" + err.Error()
	if summary == r.last {
		return
	}
	r.last = summary
	log.Error("configuration not reloaded; what was loaded before stays in use", "error", err.Error())
}

func (r *Reporter) Report(log *slog.Logger, s Status) {
	summary := s.Source + "|" + s.Error + "|" + strings.Join(s.Warnings, "|")
	if summary == r.last {
		return
	}
	r.last = summary
	log.Info("configuration loaded", "source", s.Source, "settingsApplied", s.Applied)
	if s.Error != "" {
		log.Error("settings from App Configuration not used", "error", s.Error)
	}
	for _, w := range s.Warnings {
		log.Warn("setting ignored", "setting", w)
	}
}
