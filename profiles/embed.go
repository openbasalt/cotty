// Package profiles holds the agent profiles built into cotty. The same
// files are installed to /usr/share/doc or copied by people into
// ~/.config/cotty/profiles to change them; a file there wins over the
// built-in one of the same name.
package profiles

import "embed"

// FS holds the built-in profiles, NAME.conf.
//
//go:embed *.conf
var FS embed.FS
