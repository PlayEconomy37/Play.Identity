package assets

import (
	"embed"
)

// EmbeddedFiles is our embedded file system that contains email templates and migrations
//
//go:embed "emails" "migrations"
var EmbeddedFiles embed.FS
