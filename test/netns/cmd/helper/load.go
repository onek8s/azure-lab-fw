package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// LoadResult is the final JSON line of the load subcommand (A29).
type LoadResult struct {
	Conns    int      `json:"conns"`
	OK       int      `json:"ok"`     // connections that completed every request without error
	Failed   int      `json:"failed"` // connections that hit an error
	Requests uint64   `json:"requests"`
	Bytes    uint64   `json:"bytes"`
	MaxRTTms int64    `json:"maxRttMs"`
	Errors   []string `json:"errors,omitempty"` // first few errors
}

// runLoad opens --conns parallel HTTP/1.1 (optionally TLS) keep-alive
// connections to --dst and sends a request on each every --interval until
// --duration has passed, every response streaming --bulk-kib KiB. It prints
// "READY" once every connection got its first response (or failed) and a
// LoadResult when done. A connection is never re-dialled: any error marks
// it failed, so "all connections succeeded" means each one stayed up for
// the whole run.
func runLoad(args []string) {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	dst := fs.String("dst", "", "ip:port")
	useTLS := fs.Bool("tls", false, "use TLS")
	sni := fs.String("sni", "", "TLS server name and HTTP Host")
	cas := fs.String("ca", "", "comma-separated CA PEM files trusted by the client")
	path := fs.String("path", "/", "request path")
	conns := fs.Int("conns", 10, "parallel connections")
	duration := fs.Duration("duration", 60*time.Second, "how long every connection is held")
	interval := fs.Duration("interval", 200*time.Millisecond, "pause between requests on one connection")
	ramp := fs.Duration("ramp", 2*time.Second, "spread connection set-up over this period")
	bulk := fs.Int("bulk-kib", 16, "response body size in KiB (X-Bulk-KiB)")
	timeout := fs.Duration("timeout", 15*time.Second, "per dial/handshake/request timeout")
	parse(fs, args)
	if *dst == "" || *sni == "" || *conns <= 0 {
		log.Fatal("load: --dst, --sni and --conns > 0 are required")
	}
	var tcfg *tls.Config
	if *useTLS {
		pool := x509.NewCertPool()
		for _, f := range strings.Split(*cas, ",") {
			if f == "" {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				log.Fatal(err)
			}
			pool.AppendCertsFromPEM(b)
		}
		tcfg = &tls.Config{ServerName: *sni, RootCAs: pool, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *ramp+*duration)
	defer cancel()
	var (
		res      LoadResult
		mu       sync.Mutex
		wg       sync.WaitGroup
		first    sync.WaitGroup
		reqs     atomic.Uint64
		nbytes   atomic.Uint64
		maxRTT   atomic.Int64
		finished = make(chan struct{})
	)
	res.Conns = *conns
	first.Add(*conns)
	for i := 0; i < *conns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var once sync.Once
			signal := func() { once.Do(first.Done) }
			defer signal()
			select {
			case <-time.After(*ramp * time.Duration(i) / time.Duration(*conns)):
			case <-ctx.Done():
				return
			}
			// Every connection is held for --duration from its own start.
			end := time.Now().Add(*duration)
			err := loadConn(*dst, tcfg, *sni, *path, *bulk, *interval, *timeout, end, signal,
				func(n int64, rtt time.Duration) {
					reqs.Add(1)
					nbytes.Add(uint64(n))
					for {
						m := maxRTT.Load()
						if rtt.Milliseconds() <= m || maxRTT.CompareAndSwap(m, rtt.Milliseconds()) {
							break
						}
					}
				})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Failed++
				if len(res.Errors) < 10 {
					res.Errors = append(res.Errors, fmt.Sprintf("conn %d: %v", i, err))
				}
				return
			}
			res.OK++
		}(i)
	}
	go func() { first.Wait(); ready() }()
	go func() { wg.Wait(); close(finished) }()
	<-finished
	res.Requests, res.Bytes, res.MaxRTTms = reqs.Load(), nbytes.Load(), maxRTT.Load()
	b, _ := json.Marshal(res)
	fmt.Println(string(b))
}

func loadConn(dst string, tcfg *tls.Config, host, path string, bulkKiB int, interval, timeout time.Duration,
	end time.Time, firstDone func(), done func(int64, time.Duration)) error {
	raw, err := net.DialTimeout("tcp4", dst, timeout)
	if err != nil {
		return err
	}
	defer func() { _ = raw.Close() }()
	conn := net.Conn(raw)
	if tcfg != nil {
		_ = raw.SetDeadline(time.Now().Add(timeout))
		tc := tls.Client(raw, tcfg)
		if err := tc.Handshake(); err != nil {
			return fmt.Errorf("handshake: %w", err)
		}
		conn = tc
	}
	br := bufio.NewReaderSize(conn, 16<<10)
	req, err := http.NewRequest(http.MethodGet, "http://"+host+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Bulk-KiB", fmt.Sprint(bulkKiB))
	for n := 0; ; n++ {
		start := time.Now()
		_ = conn.SetDeadline(start.Add(timeout))
		if err := req.Write(conn); err != nil {
			return fmt.Errorf("request %d: %w", n, err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return fmt.Errorf("response %d: %w", n, err)
		}
		got, err := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return fmt.Errorf("body %d: %w", n, err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("response %d: HTTP %d", n, resp.StatusCode)
		}
		if got < int64(bulkKiB)<<10 {
			return fmt.Errorf("response %d: short body %d bytes", n, got)
		}
		done(got, time.Since(start))
		firstDone()
		if resp.Close {
			return errors.New("server closed the keep-alive connection")
		}
		if time.Now().Add(interval).After(end) {
			return nil
		}
		time.Sleep(interval)
	}
}
