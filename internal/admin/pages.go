package admin

import (
	"errors"
	"html/template"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gykim-l2softlab/smart_buckler/internal/deception"
	"github.com/gykim-l2softlab/smart_buckler/internal/store"
)

// notable are the actions the overview charts: a decoy hit, a challenge
// and a WAF block (or a would-be block in detect mode).
var notable = []string{store.ActionTrapHit, store.ActionChallenged, store.ActionBlocked, store.ActionWouldBlock}

func seriesIndex(action string) int {
	switch action {
	case store.ActionTrapHit:
		return 0
	case store.ActionChallenged:
		return 1
	}
	return 2
}

// --- login ---------------------------------------------------------------

type loginData struct {
	PasswordSet bool
	Error       string
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	set, err := s.PasswordSet(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "login", "", loginData{PasswordSet: set})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	addr, now := remoteAddr(r), s.Now()
	hash, err := s.passwordHash(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if hash == "" {
		s.render(w, r, http.StatusForbidden, "login", "", loginData{})
		return
	}
	if err := s.limiter.check(addr, now); errors.Is(err, errLocked) {
		s.render(w, r, http.StatusTooManyRequests, "login", "", loginData{PasswordSet: true,
			Error: "로그인에 여러 번 실패해서 잠시 막았습니다. 15분 뒤 다시 시도해 주세요."})
		return
	}
	if !VerifyPassword(hash, r.PostFormValue("password")) {
		s.limiter.fail(addr, now)
		s.Log.Warn("admin: login failed", "client_ip", addr)
		s.render(w, r, http.StatusUnauthorized, "login", "", loginData{PasswordSet: true, Error: "비밀번호가 맞지 않습니다."})
		return
	}
	s.limiter.reset(addr)
	s.Log.Info("admin: login", "client_ip", addr)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: s.sessions.issue(hash, now), Path: "/",
		MaxAge: int(s.SessionDuration.Seconds()), HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- overview ------------------------------------------------------------

type tableRow struct {
	Label  string
	Values []int
}

type chart struct {
	SVG  template.HTML
	Rows []tableRow
}

type overviewData struct {
	Today, Now   time.Time
	Zone         string
	Blocked      int
	Sum          store.Summary
	WAFMode      string
	Hourly       chart
	Daily        chart
	TopMax       map[string]int
	Reports      []store.ReportInfo
	ReportsFound bool
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := s.Now().In(s.Location)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, s.Location)
	sum, err := s.Store.Summarize(ctx, today, now.Add(time.Millisecond), 5)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	blocks, err := s.Store.ActiveBlocks(ctx, now)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	weekStart := today.AddDate(0, 0, -6)
	counts, err := s.Store.HourlyCounts(ctx, store.EventFilter{From: weekStart, To: now.Add(time.Millisecond), Actions: notable})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reports, err := s.Store.Reports(ctx, 7)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	hours := make([]column, 24)
	for h := range hours {
		hours[h].Label = strconv.Itoa(h) + "시"
		if h <= now.Hour() {
			hours[h].Values = make([]int, 3)
		}
	}
	days := make([]column, 7)
	dayIndex := map[string]int{}
	for i := range days {
		d := weekStart.AddDate(0, 0, i)
		days[i] = column{Label: d.Format("1/2"), Values: make([]int, 3)}
		dayIndex[d.Format(time.DateOnly)] = i
	}
	for _, c := range counts {
		t := c.Hour.In(s.Location)
		k := seriesIndex(c.Action)
		if i, ok := dayIndex[t.Format(time.DateOnly)]; ok {
			days[i].Values[k] += c.N
		}
		if !t.Before(today) && hours[t.Hour()].Values != nil {
			hours[t.Hour()].Values[k] += c.N
		}
	}
	series := s.text.Series
	d := overviewData{
		Today: today, Now: now, Zone: s.Location.String(), Blocked: len(blocks), Sum: sum, WAFMode: s.Info.WAFMode,
		Hourly: chart{
			SVG:  stackedBars(chartSpec{Width: 760, Height: 230, Left: 40, Right: 12, Top: 14, Bottom: 30, LabelEvery: 3}, hours, series),
			Rows: rows(hours),
		},
		Daily: chart{
			SVG:  stackedBars(chartSpec{Width: 380, Height: 230, Left: 36, Right: 8, Top: 14, Bottom: 30, LabelEvery: 1, Class: "small"}, days, series),
			Rows: rows(days),
		},
		TopMax:  map[string]int{"clients": topMax(sum.TopClients), "paths": topMax(sum.TopPaths), "signals": topMax(sum.TopSignals)},
		Reports: reports,
	}
	for _, rc := range sum.TopRules {
		d.TopMax["rules"] = max(d.TopMax["rules"], rc.N)
	}
	s.render(w, r, http.StatusOK, "overview", "overview", d)
}

func rows(cols []column) []tableRow {
	var out []tableRow
	for _, c := range cols {
		if c.Values != nil {
			out = append(out, tableRow{Label: c.Label, Values: c.Values})
		}
	}
	return out
}

func topMax(cs []store.Count) int {
	m := 0
	for _, c := range cs {
		m = max(m, c.N)
	}
	return m
}

// --- events --------------------------------------------------------------

type eventsData struct {
	Date, Action, IP, Path string
	Actions                []string
	Events                 []store.StoredEvent
	Older, Newer           template.URL // paging links, built from url.Values
	Error                  string
}

// eventActions are the choices of the kind filter, in display order.
var eventActions = []string{store.ActionTrapHit, store.ActionBlocked, store.ActionWouldBlock, store.ActionChallenged,
	store.ActionChallengePassed, store.ActionWouldChallenge, store.ActionUnblocked, store.ActionDetected}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := eventsData{Date: q.Get("date"), Action: q.Get("action"), IP: strings.TrimSpace(q.Get("ip")),
		Path: clip(q.Get("path")), Actions: eventActions}
	var f store.EventFilter
	switch d.Action {
	case "":
		// Plain WAF warnings are noise; leave them out unless asked for.
		f.Actions = eventActions[:len(eventActions)-1]
	case "all":
	default:
		f.Actions = []string{d.Action}
	}
	if d.Date != "" {
		day, err := time.ParseInLocation(time.DateOnly, d.Date, s.Location)
		if err != nil {
			d.Error = "날짜는 2026-11-01 형식으로 적어 주세요."
		}
		f.From, f.To = day, day.AddDate(0, 0, 1)
	}
	if d.IP != "" {
		if _, err := netip.ParseAddr(d.IP); err != nil {
			d.Error = "IP 주소 형식이 아닙니다."
		}
		f.ClientIP = d.IP
	}
	f.PathContains = d.Path
	if d.Error != "" {
		s.render(w, r, http.StatusBadRequest, "events", "events", d)
		return
	}
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
	evs, err := s.Store.ListEvents(r.Context(), f, store.Page{Before: before, After: after, Limit: pageSize + 1})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var older, newer int64
	if after > 0 {
		// Ascending page: the extra row is the newest one.
		if len(evs) > pageSize {
			evs = evs[1:]
			newer = evs[0].ID
		}
		if len(evs) > 0 {
			older = evs[len(evs)-1].ID
		}
	} else {
		if len(evs) > pageSize {
			evs = evs[:pageSize]
			older = evs[len(evs)-1].ID
		}
		if before > 0 && len(evs) > 0 {
			newer = evs[0].ID
		}
	}
	d.Events = evs
	base := q
	base.Del("before")
	base.Del("after")
	if older > 0 {
		base.Set("before", strconv.FormatInt(older, 10))
		d.Older = template.URL("/events?" + base.Encode()) //nolint:gosec // encoded by url.Values
		base.Del("before")
	}
	if newer > 0 {
		base.Set("after", strconv.FormatInt(newer, 10))
		d.Newer = template.URL("/events?" + base.Encode()) //nolint:gosec // encoded by url.Values
	}
	s.render(w, r, http.StatusOK, "events", "events", d)
}

func (s *Server) event(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.notFound(w, r)
		return
	}
	e, ok, err := s.Store.EventByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		s.notFound(w, r)
		return
	}
	s.render(w, r, http.StatusOK, "event", "events", e)
}

// --- clients -------------------------------------------------------------

type clientData struct {
	IP      string
	Block   *store.Block
	Now     time.Time
	Counts  []store.Count
	Events  []store.StoredEvent
	HasMore bool
}

const clientEvents = 20

func (s *Server) client(w http.ResponseWriter, r *http.Request) {
	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		s.notFound(w, r)
		return
	}
	ctx, ip, now := r.Context(), addr.String(), s.Now()
	d := clientData{IP: ip, Now: now}
	blocks, err := s.Store.ActiveBlocks(ctx, now)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, b := range blocks {
		if b.SessionID == ip {
			d.Block = &b
		}
	}
	counts, err := s.Store.ActionCounts(ctx, store.EventFilter{ClientIP: ip, From: now.AddDate(0, 0, -7)})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, a := range eventActions {
		if counts[a] > 0 {
			d.Counts = append(d.Counts, store.Count{Key: a, N: counts[a]})
		}
	}
	evs, err := s.Store.ListEvents(ctx, store.EventFilter{ClientIP: ip}, store.Page{Limit: clientEvents + 1})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(evs) > clientEvents {
		evs, d.HasMore = evs[:clientEvents], true
	}
	d.Events = evs
	s.render(w, r, http.StatusOK, "client", "events", d)
}

// --- blocks --------------------------------------------------------------

type blocksData struct {
	Now    time.Time
	Blocks []store.Block
}

func (s *Server) blocks(w http.ResponseWriter, r *http.Request) {
	now := s.Now()
	blocks, err := s.Store.ActiveBlocks(r.Context(), now)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "blocks", "blocks", blocksData{Now: now, Blocks: blocks})
}

func (s *Server) unblockPage(w http.ResponseWriter, r *http.Request) {
	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		s.notFound(w, r)
		return
	}
	s.render(w, r, http.StatusOK, "unblock", "blocks", addr.String())
}

func (s *Server) unblock(w http.ResponseWriter, r *http.Request) {
	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		s.notFound(w, r)
		return
	}
	ip, admin := addr.String(), remoteAddr(r)
	ok, err := s.Blocklist.Unblock(r.Context(), ip)
	if err != nil {
		// The in-memory block is lifted even when the store fails.
		s.Log.Error("admin: unblock", "client_ip", ip, "err", err)
	}
	if !ok {
		http.Redirect(w, r, "/blocks?done=notblocked", http.StatusSeeOther)
		return
	}
	s.Recorder.Record(store.Event{Time: s.Now(), RequestID: "admin@" + admin, ClientIP: ip, Action: store.ActionUnblocked})
	s.Log.Info("admin: unblocked", "client_ip", ip, "admin", admin)
	http.Redirect(w, r, "/blocks?done=unblocked", http.StatusSeeOther)
}

// --- decoys --------------------------------------------------------------

type decoyRow struct {
	Path      string
	CreatedAt time.Time
	Linked    bool
	LinkAt    time.Time
	Hits      int
}

func (s *Server) decoys(w http.ResponseWriter, r *http.Request) {
	ctx, now := r.Context(), s.Now()
	decoys, err := s.Store.Decoys(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	hits, err := s.Store.PathCounts(ctx, store.EventFilter{Actions: []string{store.ActionTrapHit}})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]decoyRow, len(decoys))
	for i, dc := range decoys {
		linkAt := dc.CreatedAt.Add(deception.LinkGracePeriod)
		out[i] = decoyRow{Path: dc.Path, CreatedAt: dc.CreatedAt, Linked: !now.Before(linkAt), LinkAt: linkAt}
		// Decoy paths end in "/" and hits are anything below them, matched
		// case-insensitively like the trap itself.
		for p, n := range hits {
			lp := strings.ToLower(p)
			if lp == strings.TrimSuffix(dc.Path, "/") || strings.HasPrefix(lp, dc.Path) {
				out[i].Hits += n
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	s.render(w, r, http.StatusOK, "decoys", "decoys", out)
}

// --- settings and reports ------------------------------------------------

type settingsData struct {
	Info    Info
	Dropped uint64
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	d := settingsData{Info: s.Info}
	if s.Info.Dropped != nil {
		d.Dropped = s.Info.Dropped()
	}
	s.render(w, r, http.StatusOK, "settings", "settings", d)
}

type notifyResult struct {
	Channel string
	OK      bool
}

func (s *Server) notifyTest(w http.ResponseWriter, r *http.Request) {
	msg, err := s.Reporter.TestMessage()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var out []notifyResult
	for _, res := range s.Reporter.SendEach(r.Context(), msg) {
		// Errors may carry server responses; they go to the log, not the page.
		out = append(out, notifyResult{Channel: res.Channel, OK: res.Err == nil})
	}
	s.render(w, r, http.StatusOK, "notify", "settings", out)
}

type reportData struct {
	Day     string
	Preview bool
	Subject string
	Body    string
}

func (s *Server) reportPreview(w http.ResponseWriter, r *http.Request) {
	day := s.Now().In(s.Location).Format(time.DateOnly)
	rep, err := s.Reporter.Preview(r.Context(), day)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "report", "overview", reportData{Day: day, Preview: true, Subject: rep.Subject, Body: rep.Body})
}

func (s *Server) reportPage(w http.ResponseWriter, r *http.Request) {
	day := r.PathValue("day")
	if _, err := time.Parse(time.DateOnly, day); err != nil {
		s.notFound(w, r)
		return
	}
	body, ok, err := s.Store.Report(r.Context(), day)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		s.notFound(w, r)
		return
	}
	s.render(w, r, http.StatusOK, "report", "overview", reportData{Day: day, Body: body})
}
