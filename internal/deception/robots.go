package deception

import (
	"regexp"
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

// robotsRules are the Allow and Disallow rules of upstream's "User-agent: *"
// groups.
type robotsRules struct {
	allow, disallow []robotsRule
}

type robotsRule struct {
	length int // pattern length, for longest-match precedence
	re     *regexp.Regexp
}

// newRobotsRule compiles a path pattern with '*' wildcards and an optional
// '$' end anchor.
func newRobotsRule(pattern string) robotsRule {
	anchored := strings.HasSuffix(pattern, "$")
	parts := strings.Split(strings.TrimSuffix(pattern, "$"), "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	expr := "^" + strings.Join(parts, ".*")
	if anchored {
		expr += "$"
	}
	return robotsRule{length: len(pattern), re: regexp.MustCompile(expr)}
}

// parseRobotsRules collects rules from every group that applies to "*".
func parseRobotsRules(robots string) *robotsRules {
	r := &robotsRules{}
	inStar, prevAgent := false, false
	for _, line := range strings.Split(strings.ReplaceAll(robots, "\r\n", "\n"), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		if key == "user-agent" {
			if !prevAgent {
				inStar = false // a new group starts
			}
			inStar = inStar || value == "*"
			prevAgent = true
			continue
		}
		prevAgent = false
		if !inStar || value == "" {
			continue
		}
		switch key {
		case "allow":
			r.allow = append(r.allow, newRobotsRule(value))
		case "disallow":
			r.disallow = append(r.disallow, newRobotsRule(value))
		}
	}
	return r
}

// disallows applies RFC 9309: the longest matching rule wins, and Allow wins
// a tie.
func (r *robotsRules) disallows(p string) bool {
	longest := func(rules []robotsRule) int {
		best := -1
		for _, rule := range rules {
			if rule.length > best && rule.re.MatchString(p) {
				best = rule.length
			}
		}
		return best
	}
	d := longest(r.disallow)
	return d >= 0 && d > longest(r.allow)
}

// UpstreamDisallows reports whether upstream's robots.txt, as last served
// through smart_buckler, disallows urlPath for all crawlers. It is false until
// someone has fetched robots.txt.
func (d *Deception) UpstreamDisallows(urlPath string) bool {
	r := d.upstreamRobots.Load()
	return r != nil && r.disallows(urlPath)
}
