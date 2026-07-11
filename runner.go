package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxResponseBodyBytes int64 = 4 * 1024 * 1024

type RunSettings struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
}

type ExploitResult struct {
	Target       string               `json:"target"`
	POCName      string               `json:"poc_name"`
	Method       string               `json:"method"`
	Path         string               `json:"path"`
	URL          string               `json:"url"`
	StatusCode   int                  `json:"status_code"`
	Duration     time.Duration        `json:"duration"`
	Level        string               `json:"level"`
	Message      string               `json:"message"`
	TestedAt     time.Time            `json:"tested_at"`
	ResponseSize int64                `json:"response_size"`
	Truncated    bool                 `json:"response_truncated"`
	Evidence     *HTTPExploitEvidence `json:"evidence,omitempty"`
}

type Runner struct {
	secureClient   *http.Client
	insecureClient *http.Client
}

func NewRunner() *Runner {
	secureTransport := newHTTPTransport()
	insecureTransport := newHTTPTransport()
	insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- controlled by an explicit UI option for authorized testing.

	return &Runner{
		secureClient:   &http.Client{Transport: secureTransport},
		insecureClient: &http.Client{Transport: insecureTransport},
	}
}

func newHTTPTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 20
	transport.IdleConnTimeout = 90 * time.Second
	return transport
}

func (r *Runner) CloseIdleConnections() {
	if r == nil {
		return
	}
	if r.secureClient != nil {
		r.secureClient.CloseIdleConnections()
	}
	if r.insecureClient != nil {
		r.insecureClient.CloseIdleConnections()
	}
}

func (r *Runner) Run(targetBase string, poc *POC, settings RunSettings) ExploitResult {
	return r.RunContext(context.Background(), targetBase, poc, settings)
}

func (r *Runner) RunContext(parent context.Context, targetBase string, poc *POC, settings RunSettings) (result ExploitResult) {
	result = ExploitResult{Target: strings.TrimSpace(targetBase), TestedAt: time.Now()}
	defer func() {
		result = sanitizeResultsForExport([]ExploitResult{result})[0]
	}()
	if poc == nil {
		result.Level = "ERR"
		result.Message = "POC 数据为空"
		return result
	}
	if r == nil || r.secureClient == nil || r.insecureClient == nil {
		result.Level = "ERR"
		result.Message = "HTTP 执行器未初始化"
		return result
	}
	if parent == nil {
		parent = context.Background()
	}
	if err := parent.Err(); err != nil {
		result.POCName = poc.Name
		result.Level = "CANCEL"
		result.Message = fmt.Sprintf("[%s] 验证已取消", poc.Name)
		return result
	}
	if err := validatePOC(poc); err != nil {
		result.POCName = poc.Name
		result.Level = "ERR"
		result.Message = fmt.Sprintf("[%s] POC 配置无效: %v", poc.Name, err)
		return result
	}

	startedAt := time.Now()
	result.POCName = poc.Name
	result.Method = strings.ToUpper(strings.TrimSpace(poc.Method))
	result.Path = strings.TrimSpace(poc.Path)

	if result.Method == "" {
		result.Method = http.MethodGet
	}
	if settings.Timeout <= 0 {
		settings.Timeout = 10 * time.Second
	}

	fullURL, err := buildTargetURL(targetBase, result.Path, poc.Params)
	if err != nil {
		result.Level = "ERR"
		result.Message = fmt.Sprintf("[%s] URL 构造失败: %v", poc.Name, err)
		return result
	}
	result.URL = fullURL
	result.Target, _ = buildTargetURL(targetBase, "", "")

	var bodyReader io.Reader
	requestBody := ""
	if result.Method != http.MethodGet && result.Method != http.MethodHead && strings.TrimSpace(poc.Body) != "" {
		requestBody = poc.Body
		bodyReader = strings.NewReader(requestBody)
	}

	ctx, cancel := context.WithTimeout(parent, settings.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, result.Method, fullURL, bodyReader)
	if err != nil {
		result.Level = "ERR"
		result.Message = fmt.Sprintf("[%s] 请求构造失败: %v", poc.Name, err)
		return result
	}

	applyHeaders(req, poc)
	result.Evidence = captureRequestEvidence(req, requestBody)

	client := r.secureClient
	if settings.InsecureSkipVerify {
		client = r.insecureClient
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Duration = time.Since(startedAt)
		switch {
		case errors.Is(err, context.Canceled):
			result.Level = "CANCEL"
			result.Message = fmt.Sprintf("[%s] 验证已取消", poc.Name)
		case errors.Is(err, context.DeadlineExceeded):
			matched, reason, matchErr := evaluateMatchContext(nil, "", poc.MatchRule, result.Duration, true)
			if result.Evidence != nil {
				result.Evidence.MatchEvidence = reason
			}
			if matchErr != nil {
				result.Level = "ERR"
				result.Message = fmt.Sprintf("[%s] 匹配规则错误: %v", poc.Name, matchErr)
			} else if matched {
				result.Level = "VULN"
				result.Message = fmt.Sprintf("POC 判定成立：请求达到预期超时条件（%s）", result.Duration.Round(time.Millisecond))
			} else {
				result.Level = "ERR"
				result.Message = fmt.Sprintf("[%s] 请求在 %s 后超时；规则未将本次超时判定为命中", poc.Name, settings.Timeout)
			}
		default:
			result.Level = "ERR"
			result.Message = fmt.Sprintf("[%s] 请求失败: %v", poc.Name, err)
		}
		return result
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		result.Evidence = captureResponseEvidence(result.Evidence, resp, respBody, false)
		result.Level = "ERR"
		result.Duration = time.Since(startedAt)
		result.Message = fmt.Sprintf("[%s] 读取响应失败: %v", poc.Name, err)
		return result
	}
	result.ResponseSize = int64(len(respBody))
	if result.ResponseSize > maxResponseBodyBytes {
		result.Truncated = true
		result.ResponseSize = maxResponseBodyBytes
		respBody = respBody[:maxResponseBodyBytes]
	}
	result.Evidence = captureResponseEvidence(result.Evidence, resp, respBody, result.Truncated)

	result.StatusCode = resp.StatusCode
	result.Duration = time.Since(startedAt)

	matched, reason, err := evaluateMatchContext(resp, string(respBody), poc.MatchRule, result.Duration, false)
	if err != nil {
		if result.Evidence != nil {
			result.Evidence.MatchEvidence = "匹配规则错误: " + err.Error()
		}
		result.Level = "ERR"
		result.Message = fmt.Sprintf("[%s] 匹配规则错误: %v", poc.Name, err)
		return result
	}

	if result.Evidence != nil {
		result.Evidence.MatchEvidence = reason
	}
	durationText := result.Duration.Round(time.Millisecond).String()
	responseNote := ""
	if result.Truncated {
		responseNote = fmt.Sprintf("，响应超过 %s，仅分析前 %s", formatBytes(maxResponseBodyBytes), formatBytes(maxResponseBodyBytes))
	}
	if matched {
		result.Level = "VULN"
		result.Message = fmt.Sprintf("POC 判定成立：匹配规则满足，目标呈现对应漏洞特征 [HTTP %d · %s%s]", resp.StatusCode, durationText, responseNote)
		return result
	}

	result.Level = "SAFE"
	result.Message = fmt.Sprintf("POC 未命中：匹配规则未满足 [HTTP %d · %s%s]", resp.StatusCode, durationText, responseNote)
	return result
}

func formatBytes(size int64) string {
	const unit = int64(1024)
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := unit, 0
	for value := size / unit; value >= unit && exp < 5; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}

func validatePOC(poc *POC) error {
	if poc == nil {
		return fmt.Errorf("POC 数据为空")
	}
	method := strings.ToUpper(strings.TrimSpace(poc.Method))
	if method == "" {
		method = http.MethodGet
	}
	if !supportedRequestMethod(method) {
		return fmt.Errorf("不支持的请求方法 %q", method)
	}

	for lineNumber, line := range strings.Split(poc.Headers, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("Header 第 %d 行缺少冒号", lineNumber+1)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" || textproto.CanonicalMIMEHeaderKey(key) == "" {
			return fmt.Errorf("Header 第 %d 行名称无效", lineNumber+1)
		}
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("Header 第 %d 行值包含换行符", lineNumber+1)
		}
	}

	return validateMatchRule(poc.MatchRule)
}

func validateMatchRule(rule string) error {
	expression, err := parseMatchExpression(rule)
	if err != nil {
		return err
	}
	for _, group := range expression.groups {
		for _, condition := range group {
			if err := validateMatchCondition(condition); err != nil {
				return err
			}
		}
	}
	return nil
}

func buildTargetURL(targetBase, pocPath, rawParams string) (string, error) {
	base := strings.TrimSpace(targetBase)
	if base == "" {
		return "", fmt.Errorf("目标地址为空")
	}
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}

	parsedURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("仅支持 http 或 https 地址")
	}
	if parsedURL.Host == "" {
		return "", fmt.Errorf("目标地址缺少主机名")
	}

	cleanPath := strings.TrimSpace(pocPath)
	if cleanPath != "" {
		if !strings.HasPrefix(cleanPath, "/") {
			cleanPath = "/" + cleanPath
		}
		parsedURL.Path = strings.TrimRight(parsedURL.Path, "/") + cleanPath
	}

	if strings.TrimSpace(rawParams) != "" {
		params, err := url.ParseQuery(rawParams)
		if err != nil {
			return "", fmt.Errorf("参数格式无效: %w", err)
		}

		query := parsedURL.Query()
		for key, values := range params {
			for _, value := range values {
				query.Add(key, value)
			}
		}
		parsedURL.RawQuery = query.Encode()
	}

	return parsedURL.String(), nil
}

func applyHeaders(req *http.Request, poc *POC) {
	if req == nil || poc == nil {
		return
	}

	switch strings.ToUpper(strings.TrimSpace(poc.Method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		switch strings.ToUpper(strings.TrimSpace(poc.BodyType)) {
		case "JSON":
			req.Header.Set("Content-Type", "application/json")
		case "FORM":
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	req.Header.Set("User-Agent", "ALL1n-POC-Workbench/"+appVersion)

	lines := strings.Split(poc.Headers, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		headerKey := strings.TrimSpace(parts[0])
		headerValue := strings.TrimSpace(parts[1])
		if headerKey != "" {
			req.Header.Set(headerKey, headerValue)
		}
	}
}

func evaluateMatch(resp *http.Response, body, rule string) (bool, string, error) {
	return evaluateMatchContext(resp, body, rule, 0, false)
}

func evaluateMatchContext(resp *http.Response, body, rule string, duration time.Duration, timedOut bool) (bool, string, error) {
	if strings.TrimSpace(rule) == "" {
		return false, "未配置匹配规则", nil
	}
	if resp == nil && !timedOut {
		return false, "", fmt.Errorf("响应对象为空")
	}

	expression, err := parseMatchExpression(rule)
	if err != nil {
		return false, "", err
	}
	return expression.evaluate(matchContext{response: resp, body: body, duration: duration, timedOut: timedOut})
}

func matchStatus(statusCode int, rawRule string) (bool, string, error) {
	rule := strings.TrimSpace(strings.ToLower(rawRule))
	if rule == "" {
		return false, "", fmt.Errorf("status 规则不能为空")
	}

	if strings.HasSuffix(rule, "xx") && len(rule) == 3 {
		prefix, err := strconv.Atoi(string(rule[0]))
		if err != nil {
			return false, "", err
		}
		if prefix < 1 || prefix > 5 {
			return false, "", fmt.Errorf("status 类别必须是 1xx 到 5xx")
		}
		if statusCode/100 == prefix {
			return true, fmt.Sprintf("status 属于 %s", strings.ToUpper(rule)), nil
		}
		return false, fmt.Sprintf("status 不属于 %s", strings.ToUpper(rule)), nil
	}

	if strings.Contains(rule, "-") {
		parts := strings.SplitN(rule, "-", 2)
		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return false, "", fmt.Errorf("无效的 status 范围起始值: %w", err)
		}
		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return false, "", fmt.Errorf("无效的 status 范围结束值: %w", err)
		}
		if start < 100 || end > 599 || start > end {
			return false, "", fmt.Errorf("status 范围必须在 100-599 且起始值不大于结束值")
		}

		if statusCode >= start && statusCode <= end {
			return true, fmt.Sprintf("status 命中 %d-%d", start, end), nil
		}
		return false, fmt.Sprintf("status 未命中 %d-%d", start, end), nil
	}

	expectedStatus, err := strconv.Atoi(rule)
	if err != nil {
		return false, "", err
	}
	if expectedStatus < 100 || expectedStatus > 599 {
		return false, "", fmt.Errorf("status 必须在 100-599")
	}
	if statusCode == expectedStatus {
		return true, fmt.Sprintf("status 等于 %d", expectedStatus), nil
	}
	return false, fmt.Sprintf("status 不等于 %d", expectedStatus), nil
}

func matchHeader(resp *http.Response, rawRule string) (bool, string, error) {
	parts := strings.SplitN(rawRule, "=", 2)
	if len(parts) != 2 {
		return false, "", fmt.Errorf("header 规则应为 header:Key=Value")
	}

	headerKey := strings.TrimSpace(parts[0])
	expectedValue := strings.TrimSpace(parts[1])
	if headerKey == "" {
		return false, "", fmt.Errorf("header 名称不能为空")
	}

	currentValue := resp.Header.Get(headerKey)
	if strings.Contains(strings.ToLower(currentValue), strings.ToLower(expectedValue)) {
		return true, fmt.Sprintf("header %s 包含 %q", headerKey, expectedValue), nil
	}

	return false, fmt.Sprintf("header %s 未包含 %q", headerKey, expectedValue), nil
}
