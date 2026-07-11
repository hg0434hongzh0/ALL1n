package main

import (
	"bufio"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

const maxRawHTTPRequestBytes = 4 * 1024 * 1024

type ParsedHTTPRequest struct {
	Method   string
	Path     string
	Params   string
	Headers  string
	Body     string
	BodyType string
	Host     string
}

// parseRawHTTPRequest converts a pasted HTTP/1.x request into editable POC
// fields. Match rules and the POC name intentionally remain untouched.
func parseRawHTTPRequest(raw string) (*ParsedHTTPRequest, error) {
	if len(raw) > maxRawHTTPRequestBytes {
		return nil, fmt.Errorf("HTTP 请求包不能超过 4 MiB")
	}

	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	normalized = strings.TrimPrefix(normalized, "\ufeff")
	if strings.TrimSpace(normalized) == "" {
		return nil, fmt.Errorf("请粘贴完整的 HTTP 请求包")
	}

	headerPart, body, _ := strings.Cut(normalized, "\n\n")
	headerPart = strings.TrimSpace(headerPart)
	if firstLineEnd := strings.IndexByte(headerPart, '\n'); firstLineEnd >= 0 {
		firstLine := headerPart[:firstLineEnd]
		if strings.HasSuffix(firstLine, " HTTP/2") {
			headerPart = strings.TrimSuffix(firstLine, " HTTP/2") + " HTTP/2.0" + headerPart[firstLineEnd:]
		}
	} else if strings.HasSuffix(headerPart, " HTTP/2") {
		headerPart = strings.TrimSuffix(headerPart, " HTTP/2") + " HTTP/2.0"
	}
	if headerPart == "" {
		return nil, fmt.Errorf("HTTP 请求头为空")
	}

	// Parse only the request line and headers. The body is retained from the
	// original text so stale Content-Length values do not reject an otherwise
	// useful packet copied from a proxy or repeater.
	headerWire := strings.ReplaceAll(headerPart, "\n", "\r\n") + "\r\n\r\n"
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(headerWire)))
	if err != nil {
		return nil, fmt.Errorf("HTTP 请求格式无效: %w", err)
	}
	if req.Body != nil {
		_ = req.Body.Close()
	}

	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if !supportedRequestMethod(method) {
		return nil, fmt.Errorf("不支持的请求方法 %q", method)
	}

	path := req.URL.EscapedPath()
	if req.RequestURI == "*" {
		path = "*"
	} else if path == "" {
		path = "/"
	}

	headerNames := make([]string, 0, len(req.Header))
	for name := range req.Header {
		if isTransportManagedHeader(name) {
			continue
		}
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)

	headerLines := make([]string, 0, len(headerNames))
	for _, name := range headerNames {
		for _, value := range req.Header.Values(name) {
			headerLines = append(headerLines, fmt.Sprintf("%s: %s", name, value))
		}
	}

	return &ParsedHTTPRequest{
		Method:   method,
		Path:     path,
		Params:   req.URL.RawQuery,
		Headers:  strings.Join(headerLines, "\n"),
		Body:     body,
		BodyType: detectHTTPBodyType(req.Header.Get("Content-Type")),
		Host:     req.Host,
	}, nil
}

func supportedRequestMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodDelete, http.MethodPatch, http.MethodOptions:
		return true
	default:
		return false
	}
}

func isTransportManagedHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Host", "Content-Length", "Transfer-Encoding", "Connection", "Proxy-Connection":
		return true
	default:
		return false
	}
}

func detectHTTPBodyType(contentType string) string {
	contentType = strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	switch {
	case contentType == "application/json", strings.HasSuffix(contentType, "+json"):
		return "JSON"
	case contentType == "application/x-www-form-urlencoded":
		return "Form"
	default:
		return "Raw"
	}
}
