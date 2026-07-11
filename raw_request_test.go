package main

import (
	"strings"
	"testing"
)

func TestParseRawHTTPRequest(t *testing.T) {
	raw := "POST /api/login?debug=true HTTP/1.1\r\n" +
		"Host: old.example.com\r\n" +
		"Content-Type: application/json; charset=utf-8\r\n" +
		"Authorization: Bearer demo\r\n" +
		"Content-Length: 999\r\n" +
		"Connection: close\r\n\r\n" +
		`{"username":"admin"}`

	got, err := parseRawHTTPRequest(raw)
	if err != nil {
		t.Fatalf("parseRawHTTPRequest() error = %v", err)
	}
	if got.Method != "POST" || got.Path != "/api/login" || got.Params != "debug=true" {
		t.Fatalf("unexpected request line fields: %#v", got)
	}
	if got.Host != "old.example.com" {
		t.Fatalf("Host = %q", got.Host)
	}
	if got.BodyType != "JSON" || got.Body != `{"username":"admin"}` {
		t.Fatalf("unexpected body fields: %#v", got)
	}
	if !strings.Contains(got.Headers, "Authorization: Bearer demo") || !strings.Contains(got.Headers, "Content-Type: application/json; charset=utf-8") {
		t.Fatalf("Headers = %q", got.Headers)
	}
	for _, omitted := range []string{"Host:", "Content-Length:", "Connection:"} {
		if strings.Contains(got.Headers, omitted) {
			t.Fatalf("transport-managed header %q was retained: %q", omitted, got.Headers)
		}
	}
}

func TestParseRawHTTPRequestAbsoluteURLAndLF(t *testing.T) {
	got, err := parseRawHTTPRequest("GET https://example.com/a%20b?q=1 HTTP/1.1\nAccept: */*\n\n")
	if err != nil {
		t.Fatalf("parseRawHTTPRequest() error = %v", err)
	}
	if got.Path != "/a%20b" || got.Params != "q=1" || got.Host != "example.com" {
		t.Fatalf("unexpected parsed request: %#v", got)
	}
}

func TestParseRawHTTPRequestBurpHTTP2RequestLine(t *testing.T) {
	got, err := parseRawHTTPRequest("GET /admin HTTP/2\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")
	if err != nil {
		t.Fatalf("parseRawHTTPRequest() error = %v", err)
	}
	if got.Method != "GET" || got.Path != "/admin" || got.Host != "example.com" {
		t.Fatalf("unexpected parsed request: %#v", got)
	}
}

func TestParseRawHTTPRequestRejectsUnsupportedMethod(t *testing.T) {
	_, err := parseRawHTTPRequest("TRACE / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if err == nil || !strings.Contains(err.Error(), "不支持的请求方法") {
		t.Fatalf("error = %v", err)
	}
}

func TestDetectHTTPBodyType(t *testing.T) {
	cases := map[string]string{
		"application/json":                  "JSON",
		"application/problem+json":          "JSON",
		"application/x-www-form-urlencoded": "Form",
		"text/plain":                        "Raw",
		"":                                  "Raw",
	}
	for input, want := range cases {
		if got := detectHTTPBodyType(input); got != want {
			t.Errorf("detectHTTPBodyType(%q) = %q, want %q", input, got, want)
		}
	}
}
