package dataplane

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/ir"
	"github.com/onek8s/azure-lab-fw/internal/render/nft"
)

func TestSetWriterInNetns(t *testing.T) {
	p := &ir.Policy{
		Name: "p", PrivateRanges: ir.DefaultPrivateRanges(),
		Network: []ir.NetRule{{
			Ref: ir.RuleRef{ID: "n0"}, Action: ir.ActionAllow, Protos: ir.ProtoTCP,
			Src: ir.AddrSet{Any: true}, DstFQDNs: []string{"allowed.test"}, DstPorts: ir.PortSet{Any: true},
		}},
	}
	setName := nft.FQDNSetName("allowed.test")
	inNetns(t, func() error {
		ctx := context.Background()
		dyn := nft.DynamicSets{setName: {{Addr: netip.MustParseAddr("198.51.100.1"), Timeout: time.Hour}}}
		rs, err := nft.Render(p, nft.Env{}, dyn)
		if err != nil {
			return err
		}
		if err := Apply(ctx, rs); err != nil {
			return err
		}
		w, err := NewSetWriter()
		if err != nil {
			return err
		}
		defer w.Close()

		ip := netip.MustParseAddr("198.51.100.10")
		if err := w.Add(setName, ip, 30*time.Second); err != nil {
			return err
		}
		// Re-adding refreshes the timeout instead of failing.
		if err := w.Add(setName, ip, 120*time.Second); err != nil {
			return err
		}
		if err := w.Add(setName, netip.MustParseAddr("::ffff:198.51.100.11"), 0); err != nil {
			return err
		}
		if err := w.Add(setName, netip.MustParseAddr("2001:db8::1"), time.Minute); err == nil {
			t.Error("IPv6 accepted")
		}
		if err := w.Add("fqdn_missing.test", ip, time.Minute); err == nil {
			t.Error("add to missing set succeeded")
		}
		// The connection keeps working after an error.
		if err := w.Add(setName, ip, 120*time.Second); err != nil {
			return err
		}

		elems, err := ListSet(setName)
		if err != nil {
			return err
		}
		got := map[netip.Addr]SetElem{}
		for _, e := range elems {
			got[e.Addr] = e
		}
		if len(elems) != 3 {
			t.Errorf("elements = %+v", elems)
		}
		if e := got[netip.MustParseAddr("198.51.100.1")]; e.Expires < 50*time.Minute {
			t.Errorf("re-inlined element: %+v", e)
		}
		if e := got[ip]; e.Timeout != 120*time.Second || e.Expires < 100*time.Second {
			t.Errorf("refreshed element: %+v", e)
		}
		if e := got[netip.MustParseAddr("198.51.100.11")]; e.Timeout != time.Second {
			t.Errorf("min ttl element: %+v", e)
		}

		// A reload re-inlines the elements from DynamicSets (§6.2).
		dyn = nft.DynamicSets{}
		for _, e := range elems {
			dyn[setName] = append(dyn[setName], nft.DynElem{Addr: e.Addr, Timeout: e.Expires})
		}
		rs, err = nft.Render(p, nft.Env{}, dyn)
		if err != nil {
			return err
		}
		if err := Apply(ctx, rs); err != nil {
			return err
		}
		after, err := ListSet(setName)
		if err != nil {
			return err
		}
		if len(after) < 2 {
			t.Errorf("elements after reload = %+v", after)
		}
		return Remove(ctx)
	})
}
