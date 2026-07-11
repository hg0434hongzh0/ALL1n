package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const maxEvidenceBodyBytes = 256 * 1024

type HTTPExploitEvidence struct {
	RequestLine       string `json:"request_line,omitempty"`
	RequestHeaders    string `json:"request_headers,omitempty"`
	RequestBody       string `json:"request_body,omitempty"`
	RequestTruncated  bool   `json:"request_truncated,omitempty"`
	ResponseLine      string `json:"response_line,omitempty"`
	ResponseHeaders   string `json:"response_headers,omitempty"`
	ResponseBody      string `json:"response_body,omitempty"`
	ResponseTruncated bool   `json:"response_truncated,omitempty"`
	MatchEvidence     string `json:"match_evidence,omitempty"`
}

func captureRequestEvidence(req *http.Request, body string) *HTTPExploitEvidence {
	if req == nil {
		return nil
	}
	requestURI := redactRequestURI(req.URL.RequestURI())
	preview, truncated := evidenceBodyPreview([]byte(body), req.Header.Get("Content-Type"))
	return &HTTPExploitEvidence{
		RequestLine:      fmt.Sprintf("%s %s HTTP/1.1", req.Method, requestURI),
		RequestHeaders:   formatEvidenceHeaders(req.Header, req.Host),
		RequestBody:      preview,
		RequestTruncated: truncated,
	}
}

func captureResponseEvidence(evidence *HTTPExploitEvidence, resp *http.Response, body []byte, analyzedTruncated bool) *HTTPExploitEvidence {
	if evidence == nil {
		evidence = &HTTPExploitEvidence{}
	}
	if resp != nil {
		evidence.ResponseLine = fmt.Sprintf("HTTP/%d.%d %s", resp.ProtoMajor, resp.ProtoMinor, resp.Status)
		evidence.ResponseHeaders = formatEvidenceHeaders(resp.Header, "")
	}
	contentType := ""
	if resp != nil {
		contentType = resp.Header.Get("Content-Type")
	}
	evidence.ResponseBody, evidence.ResponseTruncated = evidenceBodyPreview(body, contentType)
	evidence.ResponseTruncated = evidence.ResponseTruncated || analyzedTruncated
	return evidence
}

func formatEvidenceHeaders(headers http.Header, host string) string {
	lines := make([]string, 0, len(headers)+1)
	if strings.TrimSpace(host) != "" {
		lines = append(lines, "Host: "+host)
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range headers.Values(name) {
			if isSensitiveName(name) {
				value = "[REDACTED]"
			}
			lines = append(lines, fmt.Sprintf("%s: %s", http.CanonicalHeaderKey(name), value))
		}
	}
	return strings.Join(lines, "\n")
}

func redactRequestURI(requestURI string) string {
	parsed, err := url.ParseRequestURI(requestURI)
	if err != nil || parsed.RawQuery == "" {
		return requestURI
	}
	query := parsed.Query()
	for key := range query {
		if isSensitiveName(key) {
			query[key] = []string{"[REDACTED]"}
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.RequestURI()
}

func evidenceBodyPreview(body []byte, contentType string) (string, bool) {
	truncated := len(body) > maxEvidenceBodyBytes
	if truncated {
		body = body[:maxEvidenceBodyBytes]
	}
	body = bytes.ToValidUTF8(body, []byte("�"))
	return redactEvidenceBody(string(body), contentType), truncated
}

func redactEvidenceBody(body, contentType string) string {
	trimmed := strings.TrimSpace(body)
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	if trimmed == "" {
		return body
	}
	if mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var value any
		if json.Unmarshal([]byte(body), &value) == nil {
			redactJSONValue(value)
			if encoded, err := json.MarshalIndent(value, "", "  "); err == nil {
				return string(encoded)
			}
		}
	}
	if mediaType == "application/x-www-form-urlencoded" {
		if values, err := url.ParseQuery(body); err == nil {
			for key := range values {
				if isSensitiveName(key) {
					values[key] = []string{"[REDACTED]"}
				}
			}
			return values.Encode()
		}
	}
	return redactKeyValueText(body)
}

func redactJSONValue(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if isSensitiveName(key) {
				typed[key] = "[REDACTED]"
				continue
			}
			redactJSONValue(child)
		}
	case []any:
		for _, child := range typed {
			redactJSONValue(child)
		}
	}
}

func redactKeyValueText(body string) string {
	parts := strings.FieldsFunc(body, func(r rune) bool { return r == '&' || r == '\n' })
	if len(parts) == 0 {
		return body
	}
	redacted := body
	for _, part := range parts {
		separator := "="
		if !strings.Contains(part, separator) {
			separator = ":"
		}
		key, value, ok := strings.Cut(part, separator)
		if !ok || !isSensitiveName(strings.Trim(strings.TrimSpace(key), `"'`)) || value == "" {
			continue
		}
		redacted = strings.ReplaceAll(redacted, part, key+separator+"[REDACTED]")
	}
	return redacted
}

func isSensitiveName(name string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(name))
	for _, marker := range []string{"authorization", "cookie", "password", "passwd", "secret", "token", "apikey", "sessionid", "privatekey"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func sanitizeResultsForExport(results []ExploitResult) []ExploitResult {
	sanitized := make([]ExploitResult, len(results))
	for index, result := range results {
		sanitized[index] = result
		sanitized[index].Target = redactURL(result.Target)
		sanitized[index].URL = redactURL(result.URL)
		sanitized[index].Path = redactRequestURI(result.Path)
		sanitized[index].Message = redactKeyValueText(result.Message)
		if result.Evidence == nil {
			continue
		}
		evidence := *result.Evidence
		evidence.RequestLine = redactEvidenceRequestLine(evidence.RequestLine)
		evidence.RequestHeaders = redactFormattedHeaders(evidence.RequestHeaders)
		evidence.ResponseHeaders = redactFormattedHeaders(evidence.ResponseHeaders)
		evidence.RequestBody = redactEvidenceBody(evidence.RequestBody, "")
		evidence.ResponseBody = redactEvidenceBody(evidence.ResponseBody, "")
		evidence.MatchEvidence = redactKeyValueText(evidence.MatchEvidence)
		sanitized[index].Evidence = &evidence
	}
	return sanitized
}

func redactURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return raw
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.RawQuery == "" {
		return raw
	}
	query := parsed.Query()
	for key := range query {
		if isSensitiveName(key) {
			query[key] = []string{"[REDACTED]"}
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func redactEvidenceRequestLine(line string) string {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return line
	}
	parts[1] = redactRequestURI(parts[1])
	return strings.Join(parts, " ")
}

func redactFormattedHeaders(raw string) string {
	lines := strings.Split(raw, "\n")
	for index, line := range lines {
		name, _, ok := strings.Cut(line, ":")
		if ok && isSensitiveName(name) {
			lines[index] = name + ": [REDACTED]"
		}
	}
	return strings.Join(lines, "\n")
}
