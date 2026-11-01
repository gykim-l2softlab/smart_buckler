// Package waf wraps the Coraza engine with the embedded OWASP CRS.
package waf

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
)

// Mode selects whether matched requests are denied.
type Mode string

// Modes.
const (
	ModeDetect Mode = "detect"
	ModeBlock  Mode = "block"
)

// Config configures the engine.
type Config struct {
	Mode Mode
	// RequestBodyLimit is the number of request body bytes inspected.
	// The remainder is forwarded without inspection (ProcessPartial).
	RequestBodyLimit int
}

// Match is a logged rule match. Matched request data is intentionally not
// exposed so it never reaches logs or the event store.
type Match struct {
	RuleID   int
	Message  string
	Severity string
}

// crsInboundBlockingRuleID is the CRS rule that denies a request once its
// inbound anomaly score reaches the threshold. Coraza reports every match as
// disruptive in block mode and none in detect mode, so this rule is what tells
// whether block mode would deny the request.
const crsInboundBlockingRuleID = 949110

// Verdict is the result of inspecting a request.
type Verdict struct {
	TxID string
	// Interrupted reports that the request must not be forwarded.
	Interrupted bool
	// Status is the HTTP status to answer with when Interrupted.
	Status  int
	Matches []Match
}

// WouldBlock reports whether block mode denies the request, regardless of mode.
func (v Verdict) WouldBlock() bool {
	if v.Interrupted {
		return true
	}
	for _, m := range v.Matches {
		if m.RuleID == crsInboundBlockingRuleID {
			return true
		}
	}
	return false
}

// WAF inspects requests. It is safe for concurrent use.
type WAF struct {
	engine coraza.WAF
}

// New loads the Coraza recommended configuration and the full CRS.
func New(cfg Config) (*WAF, error) {
	var ruleEngine string
	switch cfg.Mode {
	case ModeDetect:
		ruleEngine = "DetectionOnly"
	case ModeBlock:
		ruleEngine = "On"
	default:
		return nil, fmt.Errorf("unknown waf mode %q", cfg.Mode)
	}
	if cfg.RequestBodyLimit <= 0 {
		return nil, errors.New("request body limit must be positive")
	}

	// Response inspection is off: it buffers upstream responses and adds latency.
	// Oversized bodies are inspected partially instead of rejected, so large
	// legitimate uploads are never blocked by default.
	directives := fmt.Sprintf(`
Include @coraza.conf-recommended
SecRuleEngine %s
SecResponseBodyAccess Off
SecRequestBodyLimit %d
SecRequestBodyInMemoryLimit %d
SecRequestBodyLimitAction ProcessPartial
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
`, ruleEngine, cfg.RequestBodyLimit, cfg.RequestBodyLimit)

	engine, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(directives))
	if err != nil {
		return nil, fmt.Errorf("load coraza rules: %w", err)
	}
	return &WAF{engine: engine}, nil
}

// Inspect evaluates request phases 1 and 2. The returned close function must be
// called after the request has been fully forwarded, because the inspected body
// is replayed from the transaction buffer. close is never nil, even on error.
//
// Panics inside the engine are converted to errors so callers can fail open.
func (w *WAF) Inspect(r *http.Request) (v Verdict, closeTx func(), err error) {
	tx := w.engine.(experimental.WAFWithOptions).NewTransactionWithOptions(experimental.Options{
		Context: r.Context(),
	})
	closeTx = func() { _ = tx.Close() }

	defer func() {
		if p := recover(); p != nil {
			v = Verdict{}
			err = fmt.Errorf("coraza panic: %v", p)
		}
	}()

	v.TxID = tx.ID()
	if tx.IsRuleEngineOff() {
		return v, closeTx, nil
	}
	it, err := processRequest(tx, r)
	v.Matches = matches(tx)
	if err != nil {
		return v, closeTx, err
	}
	if it != nil {
		v.Interrupted = true
		v.Status = it.Status
		if v.Status == 0 {
			v.Status = http.StatusForbidden
		}
	}
	return v, closeTx, nil
}

// processRequest feeds the request into the transaction. It follows
// github.com/corazawaf/coraza/v3/http, which cannot be used directly because
// its middleware drops requests on engine errors instead of failing open.
func processRequest(tx types.Transaction, r *http.Request) (*types.Interruption, error) {
	if host, port, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		p, _ := strconv.Atoi(port)
		tx.ProcessConnection(host, p, "", 0)
	}
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	// net/http moves Host and Transfer-Encoding out of the header map.
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}

	if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		it, _, err := tx.ReadRequestBodyFrom(r.Body)
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		if it != nil {
			return it, nil
		}
		buffered, err := tx.RequestBodyReader()
		if err != nil {
			return nil, fmt.Errorf("buffered request body: %w", err)
		}
		// Replay the inspected prefix followed by the uninspected remainder.
		r.Body = readCloser{Reader: io.MultiReader(buffered, r.Body), Closer: r.Body}
	}

	return tx.ProcessRequestBody()
}

type readCloser struct {
	io.Reader
	io.Closer
}

func matches(tx types.Transaction) []Match {
	var out []Match
	for _, mr := range tx.MatchedRules() {
		// Skip "nolog" rules (CRS bookkeeping such as setvar and body processor setup).
		// Log() is implemented by Coraza's MatchedRule but not part of the public interface.
		if l, ok := mr.(interface{ Log() bool }); ok && !l.Log() {
			continue
		}
		if mr.Message() == "" {
			continue
		}
		out = append(out, Match{
			RuleID:   mr.Rule().ID(),
			Message:  mr.Message(),
			Severity: mr.Rule().Severity().String(),
		})
	}
	return out
}
