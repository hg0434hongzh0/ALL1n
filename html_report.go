package main

import (
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"
)

type htmlReportData struct {
	Product    string
	Version    string
	ExportedAt time.Time
	Summary    reportSummary
	Results    []ExploitResult
}

func exportResultsHTML(writer io.Writer, results []ExploitResult) error {
	if len(results) == 0 {
		return fmt.Errorf("没有可导出的验证结果")
	}
	functions := template.FuncMap{
		"levelClass":     func(level string) string { return strings.ToLower(level) },
		"formatTime":     func(value time.Time) string { return value.Local().Format("2006-01-02 15:04:05") },
		"formatDuration": func(value time.Duration) string { return value.Round(time.Millisecond).String() },
		"displayStatus": func(status int) string {
			if status == 0 {
				return "-"
			}
			return fmt.Sprintf("%d", status)
		},
	}
	tmpl, err := template.New("report").Funcs(functions).Parse(htmlReportTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(writer, htmlReportData{
		Product:    "ALL1n · By 基调听云-hongzh0",
		Version:    appVersion,
		ExportedAt: time.Now(),
		Summary:    summarizeResults(results),
		Results:    sanitizeResultsForExport(results),
	})
}

const htmlReportTemplate = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ALL1n 验证报告</title>
<style>
:root{color-scheme:dark;--bg:#080d18;--panel:#0c1422;--line:#253247;--text:#e6edf7;--muted:#8b9bb3;--primary:#4f8cff;--vuln:#fb7185;--safe:#2dd4a3;--err:#fbbf24}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 "Microsoft YaHei UI","Segoe UI",sans-serif}.wrap{max-width:1280px;margin:auto;padding:36px 24px 64px}.brand{display:flex;align-items:center;gap:16px;margin-bottom:28px}.accent{width:5px;height:56px;background:var(--primary)}h1{margin:0;font-size:30px;letter-spacing:.5px}.sub,.muted{color:var(--muted)}.meta{margin-left:auto;text-align:right}.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:20px 0}.metric,.result{background:var(--panel);border:1px solid var(--line);border-radius:10px}.metric{padding:16px}.metric strong{display:block;font-size:26px}.result{margin:14px 0;overflow:hidden}.result-head{display:grid;grid-template-columns:90px minmax(160px,1fr) minmax(140px,1fr) 90px 90px;gap:12px;padding:14px 18px;align-items:center}.badge{display:inline-block;width:max-content;padding:3px 10px;border-radius:999px;font-weight:700}.badge.vuln{background:#4a1723;color:#ff9bae}.badge.safe{background:#103b32;color:#67e8c0}.badge.err{background:#4b3510;color:#ffd66b}.badge.cancel{background:#2c3442;color:#aab6c8}.result-body{border-top:1px solid var(--line);padding:0 18px 18px}details{border-top:1px solid var(--line);padding:12px 0}summary{cursor:pointer;font-weight:700;color:#b8c9e8}pre{white-space:pre-wrap;word-break:break-word;background:#080d18;border:1px solid var(--line);padding:14px;border-radius:8px;max-height:520px;overflow:auto;font:12px/1.55 Consolas,monospace}.kv{display:grid;grid-template-columns:140px 1fr;gap:7px 14px;margin:14px 0}.warning{margin-top:24px;padding:14px;border-left:4px solid var(--err);background:#211b10}@media(max-width:800px){.grid{grid-template-columns:repeat(2,1fr)}.result-head{grid-template-columns:80px 1fr}.result-head>*:nth-child(n+3){display:none}.meta{display:none}}
</style>
</head>
<body><main class="wrap">
<header class="brand"><div class="accent"></div><div><h1>ALL1n 验证报告</h1><div class="sub">By 基调听云-hongzh0 · AUTHORIZED VERIFICATION EVIDENCE</div></div><div class="meta">版本 {{.Version}}<br>导出时间 {{formatTime .ExportedAt}}</div></header>
<section class="grid">
<div class="metric"><span class="muted">任务总数</span><strong>{{.Summary.Total}}</strong></div>
<div class="metric"><span class="muted">确认命中</span><strong>{{.Summary.Vulnerable}}</strong></div>
<div class="metric"><span class="muted">未命中</span><strong>{{.Summary.Safe}}</strong></div>
<div class="metric"><span class="muted">错误</span><strong>{{.Summary.Errors}}</strong></div>
<div class="metric"><span class="muted">取消</span><strong>{{.Summary.Cancelled}}</strong></div>
</section>
{{range .Results}}
<article class="result">
<div class="result-head"><span class="badge {{levelClass .Level}}">{{.Level}}</span><strong>{{.POCName}}</strong><span>{{.Target}}</span><span>HTTP {{displayStatus .StatusCode}}</span><span>{{formatDuration .Duration}}</span></div>
<div class="result-body">
<div class="kv"><span class="muted">验证时间</span><span>{{formatTime .TestedAt}}</span><span class="muted">请求 URL</span><span>{{.URL}}</span><span class="muted">验证说明</span><span>{{.Message}}</span></div>
{{with .Evidence}}
<details open><summary>匹配证据</summary><pre>{{.MatchEvidence}}</pre></details>
<details><summary>原始请求（已自动脱敏）</summary><pre>{{.RequestLine}}
{{.RequestHeaders}}

{{.RequestBody}}{{if .RequestTruncated}}

[请求证据已截断]{{end}}</pre></details>
<details><summary>原始响应（已自动脱敏）</summary><pre>{{.ResponseLine}}
{{.ResponseHeaders}}

{{.ResponseBody}}{{if .ResponseTruncated}}

[响应证据已截断]{{end}}</pre></details>
{{end}}
</div></article>
{{end}}
<div class="warning">本报告仅适用于已获得明确授权的安全测试。报告中的认证信息、Cookie、Token、密码等敏感字段已按默认策略脱敏。</div>
</main></body></html>`
