package certs

import (
	"container/list"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// Issuer mints client-facing leaf certificates for TLS inspection (PLAN §10).
type Issuer interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	CACertPEM() []byte
}

// Leaf certificate parameters (PLAN §6.7, S29).
const (
	LeafValidity     = 24 * time.Hour
	leafBackdate     = 5 * time.Minute
	leafRefreshAhead = time.Hour
	// DefaultCacheSize is appProxy.tls.certCacheSize's default.
	DefaultCacheSize = 512
)

// ErrNoServerName is returned when a ClientHello has no SNI.
var ErrNoServerName = errors.New("certs: ClientHello without server name")

// LeafIssuer implements Issuer with one process-wide ECDSA P-256 leaf key,
// an LRU cache of leaves keyed by name and singleflight minting.
type LeafIssuer struct {
	ca     *CA
	caPEM  []byte
	leafPK *ecdsa.PrivateKey
	now    func() time.Time

	sf singleflight.Group

	mu    sync.Mutex
	size  int
	lru   *list.List // of *cacheEntry, front = most recent
	items map[string]*list.Element

	hits, misses, mints atomic.Uint64
}

type cacheEntry struct {
	name     string
	cert     *tls.Certificate
	notAfter time.Time
}

// IssuerStats are cache counters.
type IssuerStats struct {
	Hits, Misses, Mints uint64
	Cached              int
}

// NewIssuer creates a LeafIssuer. cacheSize <= 0 uses DefaultCacheSize; now
// nil uses time.Now.
func NewIssuer(ca *CA, cacheSize int, now func() time.Time) (*LeafIssuer, error) {
	if ca == nil {
		return nil, ErrNoCA
	}
	if err := ca.validate(); err != nil {
		return nil, err
	}
	if cacheSize <= 0 {
		cacheSize = DefaultCacheSize
	}
	if now == nil {
		now = time.Now
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &LeafIssuer{
		ca: ca, caPEM: ca.CertPEM(), leafPK: k, now: now,
		size: cacheSize, lru: list.New(), items: make(map[string]*list.Element),
	}, nil
}

// CACertPEM implements Issuer.
func (i *LeafIssuer) CACertPEM() []byte { return append([]byte(nil), i.caPEM...) }

// CA returns the issuing CA.
func (i *LeafIssuer) CA() *CA { return i.ca }

// Stats returns cache counters.
func (i *LeafIssuer) Stats() IssuerStats {
	i.mu.Lock()
	n := i.lru.Len()
	i.mu.Unlock()
	return IssuerStats{Hits: i.hits.Load(), Misses: i.misses.Load(), Mints: i.mints.Load(), Cached: n}
}

// GetCertificate implements Issuer (tls.Config.GetCertificate).
func (i *LeafIssuer) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil {
		return nil, ErrNoServerName
	}
	return i.Certificate(hello.ServerName)
}

// Certificate returns a (cached) leaf for name.
func (i *LeafIssuer) Certificate(name string) (*tls.Certificate, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return nil, ErrNoServerName
	}
	if c := i.lookup(name); c != nil {
		i.hits.Add(1)
		return c, nil
	}
	i.misses.Add(1)
	v, err, _ := i.sf.Do(name, func() (any, error) {
		// Another caller may have minted while we waited for the flight.
		if c := i.lookup(name); c != nil {
			return c, nil
		}
		c, notAfter, err := i.mint(name)
		if err != nil {
			return nil, err
		}
		i.store(name, c, notAfter)
		return c, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*tls.Certificate), nil
}

func (i *LeafIssuer) lookup(name string) *tls.Certificate {
	i.mu.Lock()
	defer i.mu.Unlock()
	el, ok := i.items[name]
	if !ok {
		return nil
	}
	e := el.Value.(*cacheEntry)
	if e.notAfter.Sub(i.now()) < leafRefreshAhead {
		i.lru.Remove(el)
		delete(i.items, name)
		return nil
	}
	i.lru.MoveToFront(el)
	return e.cert
}

func (i *LeafIssuer) store(name string, c *tls.Certificate, notAfter time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if el, ok := i.items[name]; ok {
		i.lru.Remove(el)
	}
	i.items[name] = i.lru.PushFront(&cacheEntry{name: name, cert: c, notAfter: notAfter})
	for i.lru.Len() > i.size {
		old := i.lru.Back()
		i.lru.Remove(old)
		delete(i.items, old.Value.(*cacheEntry).name)
	}
}

func (i *LeafIssuer) mint(name string) (*tls.Certificate, time.Time, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, time.Time{}, err
	}
	now := i.now()
	notAfter := now.Add(LeafValidity)
	if notAfter.After(i.ca.Cert.NotAfter) {
		notAfter = i.ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-leafBackdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if a, err := netip.ParseAddr(strings.Trim(name, "[]")); err == nil {
		tmpl.IPAddresses = []net.IP{a.AsSlice()}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.ca.Cert, &i.leafPK.PublicKey, i.ca.Key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("certs: mint leaf for %q: %w", name, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, err
	}
	chain := [][]byte{der}
	for _, c := range i.ca.Chain {
		chain = append(chain, c.Raw)
	}
	chain = append(chain, i.ca.Cert.Raw)
	i.mints.Add(1)
	return &tls.Certificate{Certificate: chain, PrivateKey: i.leafPK, Leaf: leaf}, notAfter, nil
}

// CAHandler serves the CA certificate at /ca.crt (PEM).
func CAHandler(caPEM []byte) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ca.crt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="labfw-ca.crt"`)
		_, _ = w.Write(caPEM)
	})
	return mux
}

// ServeCA serves /ca.crt on addr until ctx is cancelled.
func ServeCA(ctx context.Context, addr string, caPEM []byte) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ServeCAListener(ctx, ln, caPEM)
}

// ServeCAListener is ServeCA on an existing listener.
func ServeCAListener(ctx context.Context, ln net.Listener, caPEM []byte) error {
	srv := &http.Server{
		Handler:           CAHandler(caPEM),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		<-errc
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

var _ Issuer = (*LeafIssuer)(nil)
