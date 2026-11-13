// Package setup holds the interactive first-time setup and the doctor checks.
// Everything that touches the terminal, the network or the operating system
// is injected, so the flows can be tested without either.
package setup

import "strings"

// File names and the service account used by the installers.
const (
	ConfigName  = "smart_buckler.yaml"
	DBName      = "smart_buckler.db"
	ServiceName = "smart_buckler"
	ServiceUser = "smart_buckler"
	// AdminListen is the admin UI address written by setup.
	AdminListen = "127.0.0.1:8081"
)

// Paths are where the configuration and the database live.
type Paths struct {
	Config string
	Store  string
}

// DefaultPaths returns the install locations for goos. Other systems, such
// as macOS used for development, keep both files in the current directory.
func DefaultPaths(goos string, getenv func(string) string) Paths {
	switch goos {
	case "linux":
		return Paths{
			Config: "/etc/smart_buckler/" + ConfigName,
			Store:  "/var/lib/smart_buckler/" + DBName,
		}
	case "windows":
		base := strings.TrimRight(getenv("ProgramData"), `\`)
		if base == "" {
			base = `C:\ProgramData`
		}
		dir := base + `\smart_buckler\`
		return Paths{Config: dir + ConfigName, Store: dir + DBName}
	default:
		return Paths{Config: ConfigName, Store: DBName}
	}
}

// ResolveConfig picks the configuration file when -config was not given:
// smart_buckler.yaml in the current directory if it exists, otherwise the
// installed location.
func ResolveConfig(flag string, flagSet bool, goos string, getenv func(string) string, exists func(string) bool) string {
	if flagSet {
		return flag
	}
	if exists(ConfigName) {
		return ConfigName
	}
	return DefaultPaths(goos, getenv).Config
}
