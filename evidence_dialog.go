package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func showResultEvidenceDialog(window fyne.Window, rawResult ExploitResult) {
	result := sanitizeResultsForExport([]ExploitResult{rawResult})[0]

	statusCode := "-"
	if result.StatusCode > 0 {
		statusCode = strconv.Itoa(result.StatusCode)
	} else if result.Level == "VULN" && strings.Contains(strings.ToLower(result.Message), "超时") {
		statusCode = "预期超时"
	}
	testedAt := "-"
	if !result.TestedAt.IsZero() {
		testedAt = result.TestedAt.Format("2006-01-02 15:04:05")
	}

	requestText := "未捕获请求证据"
	responseText := "未捕获响应证据"
	matchText := strings.TrimSpace(result.Message)
	if result.Evidence != nil {
		requestText = joinEvidenceParts(result.Evidence.RequestLine, result.Evidence.RequestHeaders, result.Evidence.RequestBody)
		if result.Evidence.RequestTruncated {
			requestText += "\n\n[请求证据已截断]"
		}
		responseText = joinEvidenceParts(result.Evidence.ResponseLine, result.Evidence.ResponseHeaders, result.Evidence.ResponseBody)
		if result.Evidence.ResponseTruncated {
			responseText += "\n\n[响应证据已截断]"
		}
		if strings.TrimSpace(result.Evidence.MatchEvidence) != "" {
			matchText = result.Evidence.MatchEvidence
		}
	}
	if strings.TrimSpace(matchText) == "" {
		matchText = "当前结果没有额外匹配证据。"
	}

	levelText, importance, _, iconResource := resultPresentation(result.Level)
	statusLabel := widget.NewLabelWithStyle(levelText, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	statusLabel.Importance = importance
	headline := widget.NewLabelWithStyle(resultVerdict(result), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	headline.Importance = importance
	identity := widget.NewLabel("ALL1n " + appVersion + "  ·  By 基调听云-hongzh0  ·  AUTHORIZED VERIFICATION EVIDENCE")
	identity.Importance = widget.LowImportance
	hero := widget.NewCard("POC 验证结论", "可截图复核的正式验证凭证", container.NewHBox(
		widget.NewIcon(iconResource),
		container.NewVBox(statusLabel, headline, identity),
	))

	matchLabel := widget.NewLabel(matchText)
	matchLabel.Wrapping = fyne.TextWrapWord
	matchLabel.TextStyle = fyne.TextStyle{Monospace: true}
	messageLabel := widget.NewLabel(result.Message)
	messageLabel.Wrapping = fyne.TextWrapWord

	overview := container.NewVScroll(container.NewPadded(container.NewVBox(
		hero,
		container.NewGridWithColumns(2,
			proofValueCard("验证目标", result.Target),
			proofValueCard("POC 名称", result.POCName),
		),
		proofValueCard("请求端点", strings.TrimSpace(result.Method+" "+result.URL)),
		container.NewGridWithColumns(4,
			proofValueCard("HTTP 状态", statusCode),
			proofValueCard("执行耗时", result.Duration.Round(time.Millisecond).String()),
			proofValueCard("响应大小", fmt.Sprintf("%d bytes", result.ResponseSize)),
			proofValueCard("验证时间", testedAt),
		),
		widget.NewCard("判定证据", "MATCH RULE EVIDENCE", matchLabel),
		widget.NewCard("执行结论", "RESULT MESSAGE", messageLabel),
		widget.NewCard("证据安全", "默认开启", widget.NewLabel("认证信息、Cookie、Token、密码及敏感查询参数已自动脱敏；超长请求或响应仅保留证据预览。")),
	)))

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("结论凭证", theme.ConfirmIcon(), overview),
		container.NewTabItemWithIcon("原始请求", theme.UploadIcon(), evidenceTextPanel(window, requestText)),
		container.NewTabItemWithIcon("原始响应", theme.DownloadIcon(), evidenceTextPanel(window, responseText)),
		container.NewTabItemWithIcon("匹配证据", theme.InfoIcon(), evidenceTextPanel(window, matchText)),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	proofSummary := formatProofSummary(result, statusCode, testedAt, matchText)
	copySummaryButton := widget.NewButtonWithIcon("复制证明摘要", theme.ContentCopyIcon(), func() {
		window.Clipboard().SetContent(proofSummary)
	})
	redactionLabel := widget.NewLabelWithStyle("证据已自动脱敏", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	redactionLabel.Importance = widget.SuccessImportance
	content := container.NewBorder(
		container.NewHBox(redactionLabel, widget.NewLabel(" · 仅用于已授权验证复核"), layout.NewSpacer(), copySummaryButton),
		nil, nil, nil, tabs,
	)

	detailDialog := dialog.NewCustom("POC 验证凭证", "关闭", content, window)
	detailDialog.Resize(fyne.NewSize(1120, 800))
	detailDialog.Show()
}

func proofValueCard(title, value string) fyne.CanvasObject {
	label := widget.NewLabel(defaultString(strings.TrimSpace(value), "-"))
	label.Wrapping = fyne.TextWrapWord
	label.TextStyle = fyne.TextStyle{Monospace: true}
	return widget.NewCard(title, "", label)
}

func formatProofSummary(result ExploitResult, statusCode, testedAt, matchText string) string {
	return fmt.Sprintf(`ALL1n %s · POC 验证凭证
By 基调听云-hongzh0

结论：%s
POC：%s
目标：%s
请求：%s %s
HTTP：%s
耗时：%s
响应大小：%d bytes
验证时间：%s

判定证据：
%s`,
		appVersion,
		resultVerdict(result),
		result.POCName,
		result.Target,
		result.Method,
		result.URL,
		statusCode,
		result.Duration.Round(time.Millisecond),
		result.ResponseSize,
		testedAt,
		matchText,
	)
}

func selectableLabel(text string) fyne.CanvasObject {
	entry := widget.NewEntry()
	entry.SetText(text)
	entry.Disable()
	return entry
}

func evidenceTextPanel(window fyne.Window, text string) fyne.CanvasObject {
	grid := widget.NewTextGridFromString(text)
	grid.ShowLineNumbers = true
	scroll := container.NewScroll(grid)
	copyButton := widget.NewButtonWithIcon("复制证据", theme.ContentCopyIcon(), func() {
		window.Clipboard().SetContent(text)
	})
	return container.NewBorder(
		container.NewHBox(widget.NewLabel("只读证据预览"), layout.NewSpacer(), copyButton),
		nil, nil, nil, scroll,
	)
}

func joinEvidenceParts(first, headers, body string) string {
	parts := make([]string, 0, 3)
	if strings.TrimSpace(first) != "" {
		parts = append(parts, first)
	}
	if strings.TrimSpace(headers) != "" {
		parts = append(parts, headers)
	}
	if body != "" {
		parts = append(parts, body)
	}
	if len(parts) == 0 {
		return "未捕获证据"
	}
	return strings.Join(parts, "\n\n")
}
