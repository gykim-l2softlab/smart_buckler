package score

import (
	"math"
	"time"
)

// Signal names, used as keys in the score.weights configuration.
const (
	SignalHTMLOnly         = "html_only"
	SignalHigh404          = "high_404"
	SignalPathEnumeration  = "path_enumeration"
	SignalFastRequests     = "fast_requests"
	SignalRegularInterval  = "regular_interval"
	SignalRobotsDisallowed = "robots_disallowed"
	SignalErrorRetry       = "error_retry"
	SignalWAFAnomaly       = "waf_anomaly"
)

// Signals returns the built-in signals.
func Signals() []Signal {
	return []Signal{
		htmlOnly{}, high404{}, pathEnumeration{}, fastRequests{},
		regularInterval{}, robotsDisallowed{}, errorRetry{}, wafAnomaly{},
	}
}

// DefaultWeights scores so that one strong signal (WAF anomaly, reading
// robots.txt and then visiting a disallowed path) or two medium ones reach
// DefaultThreshold, while weak signals alone never do.
func DefaultWeights() map[string]int {
	return map[string]int{
		SignalHTMLOnly:         3,
		SignalHigh404:          6,
		SignalPathEnumeration:  6,
		SignalFastRequests:     6,
		SignalRegularInterval:  4,
		SignalRobotsDisallowed: 10,
		SignalErrorRetry:       5,
		SignalWAFAnomaly:       10,
	}
}

// DefaultThreshold is the score at which a session is challenged.
const DefaultThreshold = 10

// htmlOnly: several pages without a single asset. Weak on its own because
// browsers with warm caches also skip assets.
type htmlOnly struct{}

func (htmlOnly) Name() string { return SignalHTMLOnly }
func (htmlOnly) Fired(h History) bool {
	pages, assets := 0, 0
	for _, e := range h.Entries {
		switch e.Kind {
		case KindPage:
			pages++
		case KindAsset:
			assets++
		}
	}
	return pages >= 5 && assets == 0
}

// high404: most non-asset requests are not found. Missing assets such as a
// favicon are ignored.
type high404 struct{}

func (high404) Name() string { return SignalHigh404 }
func (high404) Fired(h History) bool {
	total, notFound := 0, 0
	for _, e := range h.Entries {
		if e.Kind == KindAsset {
			continue
		}
		total++
		if e.Status == 404 {
			notFound++
		}
	}
	return total >= 10 && notFound >= 5 && notFound*2 >= total
}

// pathEnumeration: many distinct non-asset paths within a minute.
type pathEnumeration struct{}

func (pathEnumeration) Name() string { return SignalPathEnumeration }
func (pathEnumeration) Fired(h History) bool {
	seen := map[uint64]struct{}{}
	for _, e := range h.Entries {
		if e.Kind != KindAsset && h.Now.Sub(e.At) <= time.Minute {
			seen[e.PathHash] = struct{}{}
		}
	}
	return len(seen) >= 30
}

// fastRequests: 10 or more pages within any 10 second span. Only pages count,
// so a single page load with many assets or a polling API does not.
type fastRequests struct{}

func (fastRequests) Name() string { return SignalFastRequests }
func (fastRequests) Fired(h History) bool {
	times := pageTimes(h)
	for i, j := 0, 0; j < len(times); j++ {
		for times[j].Sub(times[i]) > 10*time.Second {
			i++
		}
		if j-i+1 >= 10 {
			return true
		}
	}
	return false
}

// regularInterval: the last 8 gaps between pages are nearly identical
// (coefficient of variation under 0.1), as with a fixed crawl delay.
type regularInterval struct{}

func (regularInterval) Name() string { return SignalRegularInterval }
func (regularInterval) Fired(h History) bool {
	const gaps = 8
	times := pageTimes(h)
	if len(times) < gaps+1 {
		return false
	}
	times = times[len(times)-gaps-1:]
	var sum float64
	d := make([]float64, gaps)
	for i := range d {
		d[i] = times[i+1].Sub(times[i]).Seconds()
		sum += d[i]
	}
	mean := sum / gaps
	if mean <= 0 {
		return true // all at once is as regular as it gets
	}
	var variance float64
	for _, x := range d {
		variance += (x - mean) * (x - mean)
	}
	return math.Sqrt(variance/gaps)/mean < 0.1
}

// robotsDisallowed: the session read robots.txt and then requested a path it
// disallows. Both conditions are needed: people often visit disallowed paths
// such as /search, but browsers never read robots.txt.
type robotsDisallowed struct{}

func (robotsDisallowed) Name() string { return SignalRobotsDisallowed }
func (robotsDisallowed) Fired(h History) bool {
	if !h.RobotsFetched {
		return false
	}
	for _, e := range h.Entries {
		if e.RobotsDisallowed {
			return true
		}
	}
	return false
}

// errorRetry: after an error response, the same path is requested again with
// new query parameters, repeatedly (parameter fuzzing). People correcting a
// form do this once or twice.
type errorRetry struct{}

func (errorRetry) Name() string { return SignalErrorRetry }
func (errorRetry) Fired(h History) bool {
	type key struct{ path, query uint64 }
	errored := map[uint64]bool{}
	tried := map[key]bool{}
	retries := 0
	for _, e := range h.Entries {
		k := key{e.PathHash, e.QueryHash}
		if errored[e.PathHash] && e.HasQuery && !tried[k] {
			retries++
		}
		tried[k] = true
		if e.Status >= 400 {
			errored[e.PathHash] = true
		}
	}
	return retries >= 5
}

// wafAnomaly: the WAF anomaly score of any recent request reached the
// blocking threshold, even when the WAF only detects.
type wafAnomaly struct{}

func (wafAnomaly) Name() string { return SignalWAFAnomaly }
func (wafAnomaly) Fired(h History) bool {
	for _, e := range h.Entries {
		if e.WAFWouldBlock {
			return true
		}
	}
	return false
}

func pageTimes(h History) []time.Time {
	var out []time.Time
	for _, e := range h.Entries {
		if e.Kind == KindPage {
			out = append(out, e.At)
		}
	}
	return out
}
