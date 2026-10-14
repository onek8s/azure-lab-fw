package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := realMain([]string{"version"}, &out, &errb); rc != 0 || !strings.HasPrefix(out.String(), "labfw ") {
		t.Fatalf("rc=%d out=%q", rc, out.String())
	}
}

func TestFQDNTags(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := realMain([]string{"fqdn-tags"}, &out, &errb); rc != 0 || !strings.Contains(out.String(), "WindowsUpdate") {
		t.Fatalf("rc=%d out=%q err=%q", rc, out.String(), errb.String())
	}
	out.Reset()
	if rc := realMain([]string{"fqdn-tags", "--tag", "windowsupdate"}, &out, &errb); rc != 0 || !strings.Contains(out.String(), "*.update.microsoft.com") {
		t.Fatalf("rc=%d out=%q err=%q", rc, out.String(), errb.String())
	}
	if rc := realMain([]string{"fqdn-tags", "--tag", "NoSuchTag"}, &out, &errb); rc != 1 {
		t.Fatalf("unknown tag rc=%d", rc)
	}
}

func TestCAExport(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("policy:\n  source: file\n  file: p.json\nstateDir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out1, out2, errb bytes.Buffer
	if rc := realMain([]string{"ca", "export", "--config", cfg}, &out1, &errb); rc != 0 {
		t.Fatalf("rc=%d err=%q", rc, errb.String())
	}
	if !strings.HasPrefix(out1.String(), "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("out=%q", out1.String())
	}
	if rc := realMain([]string{"ca", "export", "--state-dir", dir}, &out2, &errb); rc != 0 || out1.String() != out2.String() {
		t.Fatalf("rc=%d: CA not reused", rc)
	}
	if rc := realMain([]string{"ca"}, &out2, &errb); rc != 2 {
		t.Fatalf("rc=%d", rc)
	}
}

func TestUnknown(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := realMain([]string{"nope"}, &out, &errb); rc != 2 {
		t.Fatalf("rc=%d", rc)
	}
}
