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

func TestUnknown(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := realMain([]string{"nope"}, &out, &errb); rc != 2 {
		t.Fatalf("rc=%d", rc)
	}
}
