package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type RunSettings struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
}

type ExploitResult struct {
	POCName    string
	Method     string
	Path       string
	URL        string
	StatusCode int
	Duration   time.Duration
	Level      string
	Message    string
}

type Runner struct {
	secureClient   *http.Client
	insecureClient *http.Client
}

func NewRunner() *Runner {
	secureTransport := http.DefaultTransport.(*http.Transport).Clone()
	insecureTransport := http.DefaultTransport.(*http.Transport).Clone()
	insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	return &Runner{
		secureClient:   &http.Client{Transport: secureTransport},
		insecureClient: &http.Client{Transport: insecureTransport},
	}
}

func (r *Runner) Run(targetBase string, poc *POC, settings RunSettings) ExploitResult {
	result := ExploitResult{}
	if poc == nil {
		result.Level = "ERR"
		result.Message = "POC 数据为空"
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

	var bodyReader io.Reader
	if result.Method != http.MethodGet && strings.TrimSpace(poc.Body) != "" {
		bodyReader = strings.NewReader(poc.Body)
	}

	ctx, cancel := context.WithTimeout(context.Background(), settings.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, result.Method, fullURL, bodyReader)
	if err != nil {
		result.Level = "ERR"
		result.Message = fmt.Sprintf("[%s] 请求构造失败: %v", poc.Name, err)
		return result
	}

	applyHeaders(req, poc)

	client := r.secureClient
	if settings.InsecureSkipVerify {
		client = r.insecureClient
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Level = "ERR"
		result.Duration = time.Since(startedAt)
		result.Message = fmt.Sprintf("[%s] 请求失败: %v", poc.Name, err)
		return result
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		result.Level = "ERR"
		result.Duration = time.Since(startedAt)
		result.Message = fmt.Sprintf("[%s] 读取响应失败: %v", poc.Name, err)
		return result
	}

	result.StatusCode = resp.StatusCode
	result.Duration = time.Since(startedAt)

	matched, reason, err := evaluateMatch(resp, string(respBody), poc.MatchRule)
	if err != nil {
		result.Level = "ERR"
		result.Message = fmt.Sprintf("[%s] 匹配规则错误: %v", poc.Name, err)
		return result
	}

	durationText := result.Duration.Round(time.Millisecond).String()
	if matched {
		result.Level = "VULN"
		result.Message = fmt.Sprintf("[+] %s 命中规则（%s） [HTTP %d, %s]", poc.Name, reason, resp.StatusCode, durationText)
		return result
	}

	result.Level = "SAFE"
	result.Message = fmt.Sprintf("[-] %s 未命中规则（%s） [HTTP %d, %s]", poc.Name, reason, resp.StatusCode, durationText)
	return result
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
		switch strings.TrimSpace(poc.BodyType) {
		case "JSON":
			req.Header.Set("Content-Type", "application/json")
		case "Form":
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	req.Header.Set("User-Agent", "ALL1n-POC-Workbench/2.0")

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
	trimmedRule := strings.TrimSpace(rule)
	if trimmedRule == "" {
		return false, "未配置匹配规则", nil
	}

	expressions := strings.Split(trimmedRule, "&&")
	reasons := make([]string, 0, len(expressions))

	for _, expression := range expressions {
		expression = strings.TrimSpace(expression)
		if expression == "" {
			continue
		}

		lowerExpr := strings.ToLower(expression)
		switch {
		case strings.HasPrefix(lowerExpr, "status:"):
			ok, reason, err := matchStatus(resp.StatusCode, strings.TrimSpace(expression[len("status:"):]))
			if err != nil {
				return false, "", err
			}
			if !ok {
				return false, reason, nil
			}
			reasons = append(reasons, reason)

		case strings.HasPrefix(lowerExpr, "header:"):
			ok, reason, err := matchHeader(resp, strings.TrimSpace(expression[len("header:"):]))
			if err != nil {
				return false, "", err
			}
			if !ok {
				return false, reason, nil
			}
			reasons = append(reasons, reason)

		case strings.HasPrefix(lowerExpr, "body:"):
			needle := strings.TrimSpace(expression[len("body:"):])
			if !strings.Contains(body, needle) {
				return false, fmt.Sprintf("正文不包含 %q", needle), nil
			}
			reasons = append(reasons, fmt.Sprintf("body 包含 %q", needle))

		case strings.HasPrefix(lowerExpr, "regex:"):
			pattern := strings.TrimSpace(expression[len("regex:"):])
			matcher, err := regexp.Compile(pattern)
			if err != nil {
				return false, "", err
			}
			if !matcher.MatchString(body) {
				return false, fmt.Sprintf("正则 %q 未命中", pattern), nil
			}
			reasons = append(reasons, fmt.Sprintf("regex %q", pattern))

		default:
			if !strings.Contains(body, expression) {
				return false, fmt.Sprintf("正文不包含 %q", expression), nil
			}
			reasons = append(reasons, fmt.Sprintf("正文包含 %q", expression))
		}
	}

	if len(reasons) == 0 {
		return false, "未配置有效匹配规则", nil
	}

	return true, strings.Join(reasons, " && "), nil
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
		if statusCode/100 == prefix {
			return true, fmt.Sprintf("status 属于 %s", strings.ToUpper(rule)), nil
		}
		return false, fmt.Sprintf("status 不属于 %s", strings.ToUpper(rule)), nil
	}

	if strings.Contains(rule, "-") {
		parts := strings.SplitN(rule, "-", 2)
		if len(parts) != 2 {
			return false, "", fmt.Errorf("status 范围规则无效: %s", rawRule)
		}

		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return false, "", err
		}
		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return false, "", err
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
