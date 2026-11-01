package deception

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"html"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const (
	// bodyScanLimit bounds how much HTML is buffered while looking for <body>.
	bodyScanLimit = 64 << 10
	// robotsLimit matches Google's robots.txt size limit.
	robotsLimit = 500 << 10
)

var bodyTag = regexp.MustCompile(`(?i)<body(?:\s[^>]*)?>`)

// PrepareUpstreamRequest restricts Accept-Encoding to gzip, the only encoding
// the standard library can both decode and re-encode, so HTML responses can
// carry hidden links. robots.txt is always fetched uncompressed.
func PrepareUpstreamRequest(out *http.Request) {
	if out.URL.Path == "/robots.txt" || !acceptsGzip(out.Header.Values("Accept-Encoding")) {
		out.Header.Del("Accept-Encoding")
		return
	}
	out.Header.Set("Accept-Encoding", "gzip")
}

func acceptsGzip(values []string) bool {
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
			if !strings.EqualFold(strings.TrimSpace(coding), "gzip") {
				continue
			}
			q := strings.ReplaceAll(params, " ", "")
			return q != "q=0" && q != "q=0.0" && q != "q=0.00" && q != "q=0.000"
		}
	}
	return false
}

// ModifyResponse rewrites robots.txt and injects a hidden decoy link into HTML
// pages. It never returns an error: on any problem the response is left as is,
// because a failure here must not break the upstream service.
func (d *Deception) ModifyResponse(log *slog.Logger) func(*http.Response) error {
	return func(resp *http.Response) error {
		defer func() {
			if p := recover(); p != nil {
				log.Error("deception response panic", "panic", fmt.Sprint(p))
			}
		}()
		req := resp.Request
		if req.Method == http.MethodGet && req.URL.Path == "/robots.txt" {
			d.rewriteRobots(resp, log)
			return nil
		}
		if injectable(resp) {
			d.injectLink(resp, log)
		}
		return nil
	}
}

func (d *Deception) rewriteRobots(resp *http.Response, log *slog.Logger) {
	var upstream string
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Encoding") == "" {
		b, err := io.ReadAll(io.LimitReader(resp.Body, robotsLimit))
		if err != nil {
			log.Warn("read upstream robots.txt", "err", err)
		}
		upstream = string(b)
	}
	_ = resp.Body.Close()

	body := d.Robots(upstream)
	resp.StatusCode = http.StatusOK
	resp.Status = "200 OK"
	resp.Body = io.NopCloser(strings.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header = http.Header{
		"Content-Type":   {"text/plain; charset=utf-8"},
		"Content-Length": {strconv.Itoa(len(body))},
		"Cache-Control":  {"max-age=3600"},
	}
}

func injectable(resp *http.Response) bool {
	if resp.Request.Method != http.MethodGet || resp.StatusCode != http.StatusOK {
		return false
	}
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mt != "text/html" {
		return false
	}
	if strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Disposition")), "attachment") {
		return false
	}
	enc := resp.Header.Get("Content-Encoding")
	return enc == "" || enc == "gzip"
}

func (d *Deception) injectLink(resp *http.Response, log *slog.Logger) {
	dc, ok := d.linkDecoy(resp.Request.URL.Path)
	if !ok {
		return
	}
	// The hidden attribute is applied by the browser's UA stylesheet, so a
	// strict Content-Security-Policy cannot make the link visible the way it
	// could block an inline style.
	snippet := fmt.Sprintf(`<a href="%s/" hidden aria-hidden="true" tabindex="-1" rel="nofollow">%s</a>`,
		html.EscapeString(dc.Base), html.EscapeString(dc.Label))

	orig := resp.Body
	switch resp.Header.Get("Content-Encoding") {
	case "":
		resp.Body = readCloser{Reader: newInjector(orig, snippet), Closer: orig}
	case "gzip":
		br := bufio.NewReaderSize(orig, 4096)
		zr := gzipReaders.Get().(*gzip.Reader)
		// Validate the header on peeked bytes first, so a bad stream is still
		// forwarded untouched.
		peek, _ := br.Peek(br.Size())
		if err := zr.Reset(bytes.NewReader(peek)); err != nil {
			gzipReaders.Put(zr)
			resp.Body = readCloser{Reader: br, Closer: orig}
			return
		}
		if err := zr.Reset(br); err != nil {
			gzipReaders.Put(zr)
			log.Warn("decode gzip html", "err", err)
			resp.Body = readCloser{Reader: br, Closer: orig}
			return
		}
		resp.Body = regzip(zr, newInjector(zr, snippet), orig)
	}

	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	// The body no longer matches upstream byte for byte.
	if et := resp.Header.Get("ETag"); et != "" && !strings.HasPrefix(et, "W/") {
		resp.Header.Set("ETag", "W/"+et)
	}
}

// Compression state is large (about 1 MB per writer, 40 KB per reader), so it
// is pooled rather than allocated per response.
var (
	gzipWriters = sync.Pool{New: func() any {
		zw, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
		return zw
	}}
	gzipReaders = sync.Pool{New: func() any { return new(gzip.Reader) }}
	copyBuffers = sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}
)

// regzip compresses src through a pipe. zr is returned to its pool once src
// is drained.
func regzip(zr *gzip.Reader, src io.Reader, orig io.Closer) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		zw := gzipWriters.Get().(*gzip.Writer)
		zw.Reset(pw)
		buf := copyBuffers.Get().(*[]byte)
		_, err := io.CopyBuffer(zw, src, *buf)
		copyBuffers.Put(buf)
		if cerr := zw.Close(); err == nil {
			err = cerr
		}
		zw.Reset(io.Discard)
		gzipWriters.Put(zw)
		gzipReaders.Put(zr)
		_ = orig.Close()
		_ = pw.CloseWithError(err)
	}()
	// Closing the body also closes upstream, so a goroutine blocked on a slow
	// upstream read exits when the client goes away.
	return readCloser{Reader: pr, Closer: closerFunc(func() error {
		_ = pr.Close()
		return orig.Close()
	})}
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

type readCloser struct {
	io.Reader
	io.Closer
}

// injector inserts snippet right after the opening <body> tag. It buffers at
// most bodyScanLimit bytes while searching, then streams the rest unchanged.
type injector struct {
	src     io.Reader
	snippet string
	out     []byte
	done    bool
	err     error
}

func newInjector(src io.Reader, snippet string) *injector {
	return &injector{src: src, snippet: snippet}
}

func (in *injector) Read(p []byte) (int, error) {
	if !in.done {
		in.scan()
	}
	if len(in.out) > 0 {
		n := copy(p, in.out)
		in.out = in.out[n:]
		return n, nil
	}
	if in.err != nil {
		return 0, in.err
	}
	return in.src.Read(p)
}

func (in *injector) scan() {
	in.done = true
	buf := make([]byte, 0, 8<<10)
	chunk := make([]byte, 8<<10)
	for len(buf) < bodyScanLimit {
		n, err := in.src.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if loc := bodyTag.FindIndex(buf); loc != nil {
			out := make([]byte, 0, len(buf)+len(in.snippet))
			out = append(out, buf[:loc[1]]...)
			out = append(out, in.snippet...)
			in.out = append(out, buf[loc[1]:]...)
			in.err = err
			return
		}
		if err != nil {
			in.out, in.err = buf, err
			return
		}
	}
	in.out = buf
}
