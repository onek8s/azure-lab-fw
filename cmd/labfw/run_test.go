package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onek8s/azure-lab-fw/internal/policy"
)

func TestFetchFileSource(t *testing.T) {
	dir := t.TempDir()
	src, _ := filepath.Abs(acceptancePolicy)
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("policy:\n  source: file\n  file: "+src+"\nstateDir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.json")
	if rc, _, errs := run(t, "fetch", "--config", cfg, "--out", out); rc != 0 {
		t.Fatalf("rc=%d err=%s", rc, errs)
	}
	got, _, err := policy.LoadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	want, _, _ := policy.LoadFile(src)
	if got.Hash() != want.Hash() {
		t.Fatal("fetched bundle differs from source")
	}
	if rc, _, errs := run(t, "run", "--config", filepath.Join(dir, "missing.yaml")); rc != 1 || !strings.Contains(errs, "missing.yaml") {
		t.Fatalf("run with missing config rc=%d err=%s", rc, errs)
	}
}
