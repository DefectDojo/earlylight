package registry

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Stats counts the HTTP requests a Resolver made.
type Stats struct {
	// ManifestGets are GET requests for manifests: the requests Docker Hub
	// counts against pull rate limits.
	ManifestGets int `json:"manifest_gets"`
	// ManifestHeads are HEAD requests for manifests (not counted by Docker
	// Hub).
	ManifestHeads int `json:"manifest_heads"`
	// BlobGets are GET requests for blobs. The resolver only ever fetches
	// image configs, never layers.
	BlobGets int `json:"blob_gets"`
	// TagLists are tags/list requests (one per page).
	TagLists int `json:"tag_lists"`
	// Other counts everything else (token and ping requests).
	Other int `json:"other"`
	// Redirects counts requests that follow a redirect (blob CDNs).
	Redirects int `json:"redirects"`
	// Retries counts requests repeated after a 429, a 5xx or a network error.
	Retries int `json:"retries"`
	// RateLimitRemaining is the last "ratelimit-remaining" header Docker Hub
	// sent ("95;w=21600"), if any.
	RateLimitRemaining string `json:"rate_limit_remaining,omitempty"`
}

type statsBox struct {
	mu sync.Mutex
	s  Stats
}

func (b *statsBox) snapshot() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.s
}

func (b *statsBox) count(req *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p := req.URL.Path
	if req.Response != nil {
		// A request made to follow a redirect (Docker Hub sends blobs to a
		// CDN): the same fetch, counted once.
		b.s.Redirects++
		return
	}
	switch {
	case strings.Contains(p, "/manifests/") && req.Method == http.MethodHead:
		b.s.ManifestHeads++
	case strings.Contains(p, "/manifests/"):
		b.s.ManifestGets++
	case strings.Contains(p, "/blobs/"):
		b.s.BlobGets++
	case strings.HasSuffix(p, "/tags/list"):
		b.s.TagLists++
	default:
		b.s.Other++
	}
}

// retryTransport retries idempotent requests after HTTP 429, 500, 502, 503,
// 504 and transient network errors, with exponential backoff and jitter,
// honouring Retry-After up to a limit.
type retryTransport struct {
	base          http.RoundTripper
	headerTimeout time.Duration
	downMu        sync.Mutex
	down          map[string]bool // hosts that timed out
	retries       int
	min, max      time.Duration
	maxRetryAfter time.Duration
	stats         statsBox
	sleep         func(ctx context.Context, d time.Duration) error
}

func newRetryTransport(base http.RoundTripper, o Options) *retryTransport {
	return &retryTransport{
		base: base, retries: o.Retries, min: o.MinBackoff, max: o.MaxBackoff, maxRetryAfter: o.MaxRetryAfter,
		headerTimeout: o.RequestTimeout, down: map[string]bool{},
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}
}

func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func retryableErr(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var ht errHeaderTimeout
	if errors.As(err, &ht) || errors.Is(err, errHostTimedOut) {
		// Waiting again for a host that did not answer only multiplies the
		// delay.
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNREFUSED)
}

func retryAfter(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func (t *retryTransport) backoff(attempt int) time.Duration {
	d := t.min << attempt
	if d <= 0 || d > t.max {
		d = t.max
	}
	// Up to 20% jitter so parallel scanners do not retry in lockstep.
	return d + time.Duration(rand.Int64N(int64(d)/5+1))
}

// errHostTimedOut is returned for requests to a host that already timed out.
var errHostTimedOut = errors.New("registry host did not answer in time earlier in this scan; not contacted again")

// errHeaderTimeout is a response that did not start in time.
type errHeaderTimeout struct{ d time.Duration }

func (e errHeaderTimeout) Error() string   { return "no response within " + e.d.String() }
func (e errHeaderTimeout) Timeout() bool   { return true }
func (e errHeaderTimeout) Temporary() bool { return false }

// bodyCloser cancels the request's context when the body is closed, and stops
// waiting for a body that does not arrive in time.
type bodyCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
	timer  *time.Timer
}

func (b *bodyCloser) Close() error {
	b.timer.Stop()
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// roundTrip makes one attempt with a header deadline.
func (t *retryTransport) roundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	t.downMu.Lock()
	isDown := t.down[host]
	t.downMu.Unlock()
	if isDown {
		return nil, errHostTimedOut
	}
	ctx, cancel := context.WithCancel(req.Context())
	timer := time.AfterFunc(t.headerTimeout, cancel)
	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	if !timer.Stop() && req.Context().Err() == nil {
		// The header deadline fired.
		if err == nil {
			resp.Body.Close()
		}
		cancel()
		t.downMu.Lock()
		t.down[host] = true
		t.downMu.Unlock()
		return nil, errHeaderTimeout{t.headerTimeout}
	}
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = &bodyCloser{ReadCloser: resp.Body, cancel: cancel, timer: time.AfterFunc(2*t.headerTimeout, cancel)}
	return resp, nil
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	idempotent := (req.Method == http.MethodGet || req.Method == http.MethodHead) && (req.Body == nil || req.Body == http.NoBody)
	for attempt := 0; ; attempt++ {
		t.stats.count(req)
		resp, err := t.roundTrip(req)
		if resp != nil {
			if rl := resp.Header.Get("ratelimit-remaining"); rl != "" {
				t.stats.mu.Lock()
				t.stats.s.RateLimitRemaining = rl
				t.stats.mu.Unlock()
			}
		}
		if !idempotent || attempt >= t.retries || req.Context().Err() != nil {
			return resp, err
		}
		wait := t.backoff(attempt)
		switch {
		case err != nil:
			if !retryableErr(err) {
				return resp, err
			}
		case retryableStatus(resp.StatusCode):
			if ra := retryAfter(resp); ra > 0 {
				if ra > t.maxRetryAfter {
					return resp, nil
				}
				if ra > wait {
					wait = ra
				}
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
		default:
			return resp, nil
		}
		t.stats.mu.Lock()
		t.stats.s.Retries++
		t.stats.mu.Unlock()
		if err := t.sleep(req.Context(), wait); err != nil {
			return nil, err
		}
	}
}
