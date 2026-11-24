// Package cli holds what the tools' commands share.
package cli

import (
	"flag"
	"io"
	"os"
	"path/filepath"

	"github.com/jercle/datafetch/internal/settings"
)

// Flags returns the flag set of one tool's command.
func Flags(tool string) *flag.FlagSet {
	return flag.NewFlagSet("datafetch "+tool, flag.ContinueOnError)
}

// DefaultConfig is where a tool's configuration file is looked for when
// -config does not say: <tool>.json next to the executable.
func DefaultConfig(tool string) string {
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), tool+".json")
}

// Given reports whether a flag was set on the command line.
func Given(fs *flag.FlagSet, name string) bool {
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == name })
	return given
}

// Fetch returns how a tool's settings are read from App Configuration, or
// nil when the environment names no store or the tool was told to ignore it.
func Fetch(noAppConfig bool, tool string) (settings.Fetch, error) {
	if noAppConfig {
		return nil, nil
	}
	fetch, ok, err := settings.AppConfig(os.Getenv, tool)
	if err != nil || !ok {
		return nil, err
	}
	return fetch, nil
}

// ConfigFile reads a tool's configuration file. A file that is not there is
// only an error when -config named it and nothing else can supply the
// configuration.
func ConfigFile(fs *flag.FlagSet, path string, fetch settings.Fetch) ([]byte, error) {
	return settings.ReadFile(path, fetch != nil || !Given(fs, "config"))
}

// LogOutput opens the local log: a file to append to, or standard error.
func LogOutput(path string) (w io.Writer, done func(), err error) {
	if path == "" {
		return os.Stderr, func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}
