package main

import (
	"bytes"
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

func TestUnknown(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := realMain([]string{"nope"}, &out, &errb); rc != 2 {
		t.Fatalf("rc=%d", rc)
	}
}
