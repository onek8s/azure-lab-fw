package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// Defaults for Options.
const (
	DefaultBaseURL            = "https://management.azure.com"
	DefaultAPIVersion         = "2024-05-01"
	DefaultTimeout            = 30 * time.Second
	DefaultMaxRetries         = 4
	DefaultRetryBaseDelay     = 1 * time.Second
	DefaultRetryMaxDelay      = 30 * time.Second
	DefaultMaxRetryAfter      = 2 * time.Minute
	DefaultKeyVaultHostSuffix = ".vault.azure.net"
	DefaultIMDSBaseURL        = "http://169.254.169.254"
	DefaultIMDSTimeout        = 2 * time.Second

	// maxBodyBytes bounds a single response body (service tags are a few MiB).
	maxBodyBytes = 64 << 20
	// maxPages bounds nextLink following.
	maxPages = 1000
)

// RetryOptions controls retries of transient failures (network errors,
// HTTP 408, 429 and 5xx except 501/505).
type RetryOptions struct {
	// MaxRetries is the number of retries after the first attempt.
	// 0 means DefaultMaxRetries; a negative value disables retries.
	MaxRetries int
	// BaseDelay is the first backoff delay; it doubles on every retry.
	BaseDelay time.Duration
	// MaxDelay caps the computed exponential backoff.
	MaxDelay time.Duration
	// MaxRetryAfter caps a server-supplied Retry-After delay.
	MaxRetryAfter time.Duration
}

// Options configures a Client. The zero value is valid.
type Options struct {
	// BaseURL of the ARM endpoint (default DefaultBaseURL).
	BaseURL string
	// HTTPClient used for ARM and Key Vault requests (default: a new client
	// with http.DefaultTransport). Its Timeout is not used; see Timeout.
	HTTPClient *http.Client
	// APIVersion is the Microsoft.Network API version used when a call is
	// given an empty apiVersion (default DefaultAPIVersion).
	APIVersion string
	// Timeout per HTTP attempt (default DefaultTimeout).
	Timeout time.Duration
	// Retry settings.
	Retry RetryOptions
	// KeyVaultHostSuffix is the host suffix secret IDs must have
	// (default DefaultKeyVaultHostSuffix). Overridable for tests.
	KeyVaultHostSuffix string
	// IMDSBaseURL (default DefaultIMDSBaseURL), overridable for tests.
	IMDSBaseURL string
	// IMDSHTTPClient used for IMDS (default: no proxy, DefaultIMDSTimeout).
	IMDSHTTPClient *http.Client
	// Logger for retry diagnostics (default: discard).
	Logger *slog.Logger
}

// Client talks to ARM, Key Vault and IMDS using plain net/http.
type Client struct {
	baseURL    *url.URL
	http       *http.Client
	apiVersion string
	timeout    time.Duration
	retry      RetryOptions
	kvSuffix   string
	imdsURL    string
	imdsHTTP   *http.Client
	log        *slog.Logger
	tokens     *tokenCache

	// test hooks
	sleep  func(ctx context.Context, d time.Duration) error
	now    func() time.Time
	jitter func(d time.Duration) time.Duration
}

// New returns a Client using cred for ARM and Key Vault tokens. cred may be
// nil when only IMDS is used.
func New(cred azcore.TokenCredential, opts Options) (*Client, error) {
	base := opts.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("invalid ARM base URL %q", base)
	}
	c := &Client{
		baseURL:    u,
		http:       opts.HTTPClient,
		apiVersion: opts.APIVersion,
		timeout:    opts.Timeout,
		retry:      opts.Retry,
		kvSuffix:   opts.KeyVaultHostSuffix,
		imdsURL:    strings.TrimRight(opts.IMDSBaseURL, "/"),
		imdsHTTP:   opts.IMDSHTTPClient,
		log:        opts.Logger,
		sleep:      sleepCtx,
		now:        time.Now,
		jitter:     fullHalfJitter,
	}
	if c.http == nil {
		c.http = &http.Client{}
	}
	if c.apiVersion == "" {
		c.apiVersion = DefaultAPIVersion
	}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	switch {
	case c.retry.MaxRetries == 0:
		c.retry.MaxRetries = DefaultMaxRetries
	case c.retry.MaxRetries < 0:
		c.retry.MaxRetries = 0
	}
	if c.retry.BaseDelay <= 0 {
		c.retry.BaseDelay = DefaultRetryBaseDelay
	}
	if c.retry.MaxDelay <= 0 {
		c.retry.MaxDelay = DefaultRetryMaxDelay
	}
	if c.retry.MaxRetryAfter <= 0 {
		c.retry.MaxRetryAfter = DefaultMaxRetryAfter
	}
	if c.kvSuffix == "" {
		c.kvSuffix = DefaultKeyVaultHostSuffix
	}
	if c.imdsURL == "" {
		c.imdsURL = DefaultIMDSBaseURL
	}
	if c.imdsHTTP == nil {
		c.imdsHTTP = &http.Client{
			Transport: &http.Transport{Proxy: nil}, // IMDS must never be proxied
			Timeout:   DefaultIMDSTimeout,
		}
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if cred != nil {
		c.tokens = &tokenCache{cred: cred, now: func() time.Time { return c.now() }}
	}
	return c, nil
}

// ARMError is a non-2xx response from ARM or Key Vault. Code and Message
// come from the `{"error":{"code","message"}}` body when present.
type ARMError struct {
	StatusCode int
	Code       string
	Message    string
	URL        string // request URL without query
}

func (e *ARMError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "azure: HTTP %d", e.StatusCode)
	if e.URL != "" {
		fmt.Fprintf(&b, " for %s", e.URL)
	}
	if e.Code != "" {
		fmt.Fprintf(&b, ": %s", e.Code)
	}
	if e.Message != "" {
		fmt.Fprintf(&b, ": %s", e.Message)
	}
	return b.String()
}

// IsNotFound reports whether err is (or wraps) an ARMError with status 404.
func IsNotFound(err error) bool {
	var ae *ARMError
	return errors.As(err, &ae) && ae.StatusCode == http.StatusNotFound
}

func parseARMError(status int, reqURL string, body []byte) *ARMError {
	e := &ARMError{StatusCode: status, URL: reqURL}
	var env struct {
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil && env.Error != nil {
		e.Code, e.Message = env.Error.Code, env.Error.Message
	} else if s := strings.TrimSpace(string(body)); s != "" {
		if len(s) > 512 {
			s = s[:512] + "…"
		}
		e.Message = s
	}
	return e
}

// GetJSON GETs path (relative to BaseURL, typically a full resource ID, or
// an absolute URL on the same host) with api-version apiVersion (empty =
// Options.APIVersion) and returns the raw JSON body.
func (c *Client) GetJSON(ctx context.Context, path, apiVersion string) (json.RawMessage, error) {
	u, err := c.armURL(path, apiVersion)
	if err != nil {
		return nil, err
	}
	b, err := c.get(ctx, ARMScope, u)
	if err != nil {
		return nil, err
	}
	if !json.Valid(b) {
		return nil, fmt.Errorf("azure: invalid JSON from %s", redact(u))
	}
	return json.RawMessage(b), nil
}

// List GETs a collection and follows nextLink, returning the concatenated
// `value` arrays.
func (c *Client) List(ctx context.Context, path, apiVersion string) ([]json.RawMessage, error) {
	u, err := c.armURL(path, apiVersion)
	if err != nil {
		return nil, err
	}
	var out []json.RawMessage
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("azure: more than %d pages listing %s", maxPages, path)
		}
		b, err := c.get(ctx, ARMScope, u)
		if err != nil {
			return nil, err
		}
		var p struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"nextLink"`
		}
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, fmt.Errorf("azure: decode page of %s: %w", redact(u), err)
		}
		out = append(out, p.Value...)
		if p.NextLink == "" {
			return out, nil
		}
		if u, err = c.armURL(p.NextLink, apiVersion); err != nil {
			return nil, fmt.Errorf("azure: nextLink: %w", err)
		}
	}
}

// armURL resolves path against the base URL and sets api-version if the
// path does not already carry one. Absolute URLs must point at the base
// host so tokens never leak to other hosts.
func (c *Client) armURL(path, apiVersion string) (*url.URL, error) {
	if apiVersion == "" {
		apiVersion = c.apiVersion
	}
	var u *url.URL
	if strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "http://") {
		p, err := url.Parse(path)
		if err != nil {
			return nil, fmt.Errorf("azure: parse URL: %w", err)
		}
		if p.Scheme != c.baseURL.Scheme || !strings.EqualFold(p.Host, c.baseURL.Host) {
			return nil, fmt.Errorf("azure: URL %s is not on %s", redact(p), c.baseURL.Host)
		}
		u = p
	} else {
		p, err := url.Parse("/" + strings.TrimLeft(path, "/"))
		if err != nil {
			return nil, fmt.Errorf("azure: parse path: %w", err)
		}
		u = c.baseURL.JoinPath(p.Path)
		u.RawQuery = p.RawQuery
	}
	q := u.Query()
	if q.Get("api-version") == "" {
		q.Set("api-version", apiVersion)
		u.RawQuery = q.Encode()
	}
	return u, nil
}

// get performs an authenticated GET with retries and returns the body of a
// 2xx response.
func (c *Client) get(ctx context.Context, scope string, u *url.URL) ([]byte, error) {
	if c.tokens == nil {
		return nil, errors.New("azure: client has no credential")
	}
	var lastErr error
	for attempt := 0; ; attempt++ {
		body, retryAfter, retryable, err := c.attempt(ctx, scope, u)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retryable || attempt >= c.retry.MaxRetries {
			if retryable && attempt > 0 {
				return nil, fmt.Errorf("azure: giving up after %d attempts: %w", attempt+1, lastErr)
			}
			return nil, lastErr
		}
		delay := c.backoff(attempt)
		if retryAfter > 0 {
			delay = min(retryAfter, c.retry.MaxRetryAfter)
		}
		c.log.Debug("azure request retry", "url", redact(u), "attempt", attempt+1, "delay", delay, "err", err)
		if err := c.sleep(ctx, delay); err != nil {
			return nil, fmt.Errorf("%w (last error: %w)", err, lastErr)
		}
	}
}

// attempt does one HTTP round trip.
func (c *Client) attempt(ctx context.Context, scope string, u *url.URL) (body []byte, retryAfter time.Duration, retryable bool, err error) {
	token, err := c.tokens.get(ctx, scope)
	if err != nil {
		return nil, 0, false, err
	}
	actx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(actx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, false, fmt.Errorf("azure: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "labfw")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, false, fmt.Errorf("azure: GET %s: %w", redact(u), ctx.Err())
		}
		return nil, 0, true, fmt.Errorf("azure: GET %s: %w", redact(u), err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, false, fmt.Errorf("azure: read %s: %w", redact(u), ctx.Err())
		}
		return nil, 0, true, fmt.Errorf("azure: read %s: %w", redact(u), err)
	}
	if len(b) > maxBodyBytes {
		return nil, 0, false, fmt.Errorf("azure: response from %s exceeds %d bytes", redact(u), maxBodyBytes)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return bytes.TrimSpace(b), 0, false, nil
	}
	ae := parseARMError(resp.StatusCode, redact(u), b)
	sc := resp.StatusCode
	retryable = sc == http.StatusRequestTimeout || sc == http.StatusTooManyRequests ||
		(sc >= 500 && sc != http.StatusNotImplemented && sc != http.StatusHTTPVersionNotSupported)
	if sc == http.StatusTooManyRequests || sc == http.StatusServiceUnavailable {
		retryAfter = parseRetryAfter(resp.Header, c.now())
	}
	return nil, retryAfter, retryable, ae
}

// backoff returns the jittered exponential delay before retry attempt+1.
func (c *Client) backoff(attempt int) time.Duration {
	d := c.retry.BaseDelay
	for i := 0; i < attempt && d < c.retry.MaxDelay; i++ {
		d *= 2
	}
	return c.jitter(min(d, c.retry.MaxDelay))
}

// fullHalfJitter returns a random duration in [d/2, d].
func fullHalfJitter(d time.Duration) time.Duration {
	if d <= 1 {
		return d
	}
	half := d / 2
	return half + rand.N(d-half+1)
}

// parseRetryAfter reads retry-after-ms / x-ms-retry-after-ms (Azure) or
// Retry-After (seconds or HTTP date). Returns 0 when absent or invalid.
func parseRetryAfter(h http.Header, now time.Time) time.Duration {
	for _, k := range []string{"Retry-After-Ms", "X-Ms-Retry-After-Ms"} {
		if v := h.Get(k); v != "" {
			if ms, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && ms > 0 {
				return time.Duration(ms) * time.Millisecond
			}
		}
	}
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if s, err := strconv.ParseInt(v, 10, 64); err == nil {
		if s <= 0 {
			return 0
		}
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// redact returns u without its query string (for logs and errors).
func redact(u *url.URL) string {
	r := *u
	r.RawQuery = ""
	r.User = nil
	return r.String()
}
