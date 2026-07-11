package main

import "testing"

func TestParseTargetsNormalizesDeduplicatesAndSkipsComments(t *testing.T) {
	t.Parallel()

	targets, err := parseTargets("# production\nexample.com\nhttp://example.com\nhttps://two.example/base\n")
	if err != nil {
		t.Fatalf("parseTargets failed: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2: %#v", len(targets), targets)
	}
	if targets[0] != "http://example.com" {
		t.Fatalf("unexpected normalized target: %s", targets[0])
	}
}

func TestParseTargetsReportsLineNumber(t *testing.T) {
	t.Parallel()

	if _, err := parseTargets("example.com\nfile:///tmp/x"); err == nil || err.Error() == "" {
		t.Fatal("expected invalid target error")
	}
}
