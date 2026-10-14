package daemon

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/onek8s/azure-lab-fw/internal/azure"
)

// blockingCred is a credential whose token requests hang until cancelled
// (IMDS unreachable, as in the netns suite).
type blockingCred struct{}

func (blockingCred) GetToken(ctx context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	<-ctx.Done()
	return azcore.AccessToken{}, ctx.Err()
}

// TestKeyVaultCAFetchDoesNotBlock: a hanging Key Vault fetch must not hold
// up start-up or refreshes (found by the netns suite, A18/A19); the local
// CA is used until Key Vault answers.
func TestKeyVaultCAFetchDoesNotBlock(t *testing.T) {
	e := newEnv(t, "acceptance")
	az, err := azure.New(blockingCred{}, azure.Options{})
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(e.cfg, Deps{
		Source: e.src, Applier: e.applier, SetWriter: nopSetWriter{}, DisableNFLog: true, Azure: az,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- d.Start(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Start blocked on the Key Vault CA fetch")
	}
	t.Cleanup(d.Stop)
	if n := e.applier.count(); n != 1 {
		t.Fatalf("applies after start = %d, want 1", n)
	}
	st := d.Status()
	if st.Health != "ok" || st.CASource != "local" {
		t.Fatalf("status = %+v, want ok with the local CA while Key Vault is pending", st)
	}
	rdone := make(chan error, 1)
	go func() { rdone <- d.Refresh(context.Background()) }()
	select {
	case err := <-rdone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Refresh blocked behind the Key Vault CA fetch")
	}
}
