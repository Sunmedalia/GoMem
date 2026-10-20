// Package docs embeds the pinned acceptance inventory for offline diagnostics.
package docs

import _ "embed"

//go:embed capabilities.json
var Capabilities []byte
