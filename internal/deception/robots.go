package deception

import (
	"strings"
)

// Robots returns upstream's robots.txt with every decoy disallowed. When
// upstream has none, pass an empty string.
//
// Crawlers obey only the most specific group matching their user agent
// (RFC 9309), so the Disallow lines are added to every group, and a
// "User-agent: *" group is added when none exists. Well-behaved crawlers then
// never request a decoy, while clients that read robots.txt for targets do.
func (d *Deception) Robots(upstream string) string {
	var disallow strings.Builder
	for _, dc := range d.decoys {
		disallow.WriteString("Disallow: " + dc.Base + "/\n")
	}

	lines := strings.Split(strings.ReplaceAll(upstream, "\r\n", "\n"), "\n")
	var (
		out         strings.Builder
		hasWildcard bool
	)
	for i, line := range lines {
		if i == len(lines)-1 && line == "" {
			break // trailing newline
		}
		out.WriteString(line + "\n")
		agent, ok := userAgent(line)
		if !ok {
			continue
		}
		if agent == "*" {
			hasWildcard = true
		}
		// Insert after the last User-agent line of a group.
		if i+1 >= len(lines) || !isUserAgent(lines[i+1]) {
			out.WriteString(disallow.String())
		}
	}
	if !hasWildcard {
		if out.Len() > 0 {
			out.WriteString("\n")
		}
		out.WriteString("User-agent: *\n" + disallow.String())
	}
	return out.String()
}

func userAgent(line string) (string, bool) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	key, value, ok := strings.Cut(line, ":")
	if !ok || !strings.EqualFold(strings.TrimSpace(key), "user-agent") {
		return "", false
	}
	return strings.TrimSpace(value), true
}

func isUserAgent(line string) bool {
	_, ok := userAgent(line)
	return ok
}
