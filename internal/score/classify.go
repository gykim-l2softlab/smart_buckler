package score

import (
	"mime"
	"path"
	"strings"
)

var assetExt = map[string]bool{
	".css": true, ".js": true, ".mjs": true, ".map": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".avif": true, ".svg": true, ".ico": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".mp4": true, ".webm": true, ".mp3": true, ".ogg": true, ".wav": true,
}

// IsAssetPath reports whether the path has a static asset extension.
func IsAssetPath(p string) bool {
	return assetExt[strings.ToLower(path.Ext(p))]
}

// Classify determines a request's Kind from its path and response.
func Classify(urlPath, contentType string, status int) Kind {
	mt, _, _ := mime.ParseMediaType(contentType)
	switch {
	case IsAssetPath(urlPath),
		mt == "text/css",
		strings.Contains(mt, "javascript"),
		strings.HasPrefix(mt, "image/"),
		strings.HasPrefix(mt, "font/"),
		strings.HasPrefix(mt, "video/"),
		strings.HasPrefix(mt, "audio/"):
		return KindAsset
	case mt == "text/html", mt == "application/xhtml+xml", status == 404:
		return KindPage
	default:
		return KindOther
	}
}
