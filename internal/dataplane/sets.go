package dataplane

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/google/nftables"
)

// SetWriter adds elements to the dynamic FQDN sets of table inet labfw over
// netlink (§6.3). It implements the dnsproxy SetWriter interface. It is safe
// for concurrent use.
type SetWriter struct {
	mu   sync.Mutex
	conn *nftables.Conn
}

// NewSetWriter opens a netlink connection in the current network namespace.
func NewSetWriter() (*SetWriter, error) {
	c, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("nftables netlink: %w", err)
	}
	return &SetWriter{conn: c}, nil
}

// Close releases the netlink connection.
func (w *SetWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.conn.CloseLasting()
}

func labfwTable() *nftables.Table {
	return &nftables.Table{Name: Table, Family: nftables.TableFamilyINet}
}

func timeoutSet(name string) *nftables.Set {
	return &nftables.Set{Table: labfwTable(), Name: name, KeyType: nftables.TypeIPAddr, HasTimeout: true}
}

// Add inserts ip into set with the given timeout (rounded up to whole
// milliseconds, at least 1s). If the element already exists its timeout is
// reset to ttl: the batch is add (no-op if present) + delete + add, applied
// atomically, so the element is never absent.
func (w *SetWriter) Add(set string, ip netip.Addr, ttl time.Duration) error {
	ip = ip.Unmap()
	if !ip.Is4() {
		return fmt.Errorf("set %s: %s is not an IPv4 address", set, ip)
	}
	ttl = max(ttl, time.Second).Round(time.Millisecond)
	s := timeoutSet(set)
	elem := []nftables.SetElement{{Key: ip.AsSlice(), Timeout: ttl}}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.conn.SetAddElements(s, elem); err != nil {
		return err
	}
	if err := w.conn.SetDeleteElements(s, elem); err != nil {
		return err
	}
	if err := w.conn.SetAddElements(s, elem); err != nil {
		return err
	}
	if err := w.conn.Flush(); err != nil {
		return fmt.Errorf("set %s add %s: %w", set, ip, err)
	}
	return nil
}

// SetElem is an element read back from a set.
type SetElem struct {
	Addr    netip.Addr
	Timeout time.Duration // configured timeout (0 if none)
	Expires time.Duration // remaining lifetime (0 if none)
}

// ListSet returns the IPv4 elements of a set in table inet labfw, sorted by
// address. Used by tests and to rebuild DynamicSets before a reload.
func ListSet(set string) ([]SetElem, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}
	s, err := c.GetSetByName(labfwTable(), set)
	if err != nil {
		return nil, fmt.Errorf("set %s: %w", set, err)
	}
	if s == nil {
		return nil, errors.New("set " + set + " not found")
	}
	elems, err := c.GetSetElements(s)
	if err != nil {
		return nil, fmt.Errorf("set %s elements: %w", set, err)
	}
	var out []SetElem
	for _, e := range elems {
		if e.IntervalEnd {
			continue
		}
		a, ok := netip.AddrFromSlice(e.Key)
		if !ok || !a.Is4() {
			continue
		}
		out = append(out, SetElem{Addr: a, Timeout: e.Timeout, Expires: e.Expires})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.Less(out[j].Addr) })
	return out, nil
}
