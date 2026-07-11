package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type resultListRow struct {
	widget.BaseWidget
	result ExploitResult
}

func newResultListRow() *resultListRow {
	row := &resultListRow{}
	row.ExtendBaseWidget(row)
	return row
}

func (r *resultListRow) SetResult(result ExploitResult) {
	r.result = result
	r.Refresh()
}

func (r *resultListRow) CreateRenderer() fyne.WidgetRenderer {
	accent := canvas.NewRectangle(theme.Color(theme.ColorNamePrimary))
	accent.SetMinSize(fyne.NewSize(7, 0))
	icon := widget.NewIcon(theme.InfoIcon())
	level := widget.NewLabelWithStyle("等待验证", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	proof := widget.NewLabelWithStyle("ALL1n · AUTHORIZED VERIFICATION", fyne.TextAlignTrailing, fyne.TextStyle{Monospace: true})
	proof.Importance = widget.LowImportance

	poc := widget.NewLabelWithStyle("POC", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	poc.Truncation = fyne.TextTruncateEllipsis
	verdict := widget.NewLabelWithStyle("判定结论", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	verdict.Truncation = fyne.TextTruncateEllipsis
	target := widget.NewLabel("")
	target.Truncation = fyne.TextTruncateEllipsis
	url := widget.NewLabel("")
	url.TextStyle = fyne.TextStyle{Monospace: true}
	url.Importance = widget.LowImportance
	url.Truncation = fyne.TextTruncateEllipsis
	evidence := widget.NewLabel("")
	evidence.Importance = widget.LowImportance
	evidence.Truncation = fyne.TextTruncateEllipsis
	metrics := widget.NewLabel("")
	metrics.TextStyle = fyne.TextStyle{Monospace: true}
	metrics.Importance = widget.LowImportance
	metrics.Alignment = fyne.TextAlignTrailing

	header := container.NewBorder(nil, nil, container.NewHBox(icon, level), proof, layout.NewSpacer())
	content := container.NewVBox(header, poc, verdict, target, url, container.NewBorder(nil, nil, evidence, metrics, layout.NewSpacer()))
	background := canvas.NewRectangle(theme.Color(colorNameSurface))
	border := canvas.NewRectangle(theme.Color(colorNameSurfaceBorder))
	card := container.NewStack(border, container.NewPadded(container.NewStack(background, container.NewPadded(content))))
	root := container.NewBorder(nil, nil, accent, nil, card)

	return &resultListRowRenderer{
		row: r, accent: accent, background: background, border: border, icon: icon,
		level: level, proof: proof, poc: poc, verdict: verdict, target: target, url: url,
		evidence: evidence, metrics: metrics, root: root,
	}
}

type resultListRowRenderer struct {
	row        *resultListRow
	accent     *canvas.Rectangle
	background *canvas.Rectangle
	border     *canvas.Rectangle
	icon       *widget.Icon
	level      *widget.Label
	proof      *widget.Label
	poc        *widget.Label
	verdict    *widget.Label
	target     *widget.Label
	url        *widget.Label
	evidence   *widget.Label
	metrics    *widget.Label
	root       *fyne.Container
}

func (r *resultListRowRenderer) Layout(size fyne.Size)        { r.root.Resize(size) }
func (r *resultListRowRenderer) MinSize() fyne.Size           { return fyne.NewSize(700, 148) }
func (r *resultListRowRenderer) Objects() []fyne.CanvasObject { return []fyne.CanvasObject{r.root} }
func (r *resultListRowRenderer) Destroy()                     {}
func (r *resultListRowRenderer) Refresh() {
	result := r.row.result
	levelText, importance, colorName, icon := resultPresentation(result.Level)
	r.level.SetText(levelText)
	r.level.Importance = importance
	r.poc.SetText(defaultString(strings.TrimSpace(result.POCName), "未命名 POC"))
	r.verdict.SetText(resultVerdict(result))
	r.verdict.Importance = importance
	r.target.SetText("验证目标  " + defaultString(strings.TrimSpace(result.Target), "-"))
	r.url.SetText(defaultString(strings.TrimSpace(result.Method), "HTTP") + "  " + defaultString(strings.TrimSpace(result.URL), "-"))
	r.evidence.SetText("判定依据  " + resultEvidenceHeadline(result))

	status := "HTTP -"
	if result.StatusCode > 0 {
		status = "HTTP " + strconv.Itoa(result.StatusCode)
	} else if strings.EqualFold(result.Level, "VULN") && strings.Contains(strings.ToLower(result.Message), "超时") {
		status = "EXPECTED TIMEOUT"
	}
	testedAt := "时间 -"
	if !result.TestedAt.IsZero() {
		testedAt = result.TestedAt.Format("2006-01-02 15:04:05")
	}
	r.metrics.SetText(fmt.Sprintf("%s   ·   %s   ·   %s   ·   %s", status, result.Duration.Round(time.Millisecond), formatCompactBytes(result.ResponseSize), testedAt))

	r.accent.FillColor = theme.Color(colorName)
	r.background.FillColor = theme.Color(colorNameSurface)
	r.border.FillColor = theme.Color(colorNameSurfaceBorder)
	r.icon.SetResource(icon)
	for _, object := range []fyne.CanvasObject{r.level, r.proof, r.poc, r.verdict, r.target, r.url, r.evidence, r.metrics, r.accent, r.background, r.border, r.root} {
		object.Refresh()
	}
}

func resultPresentation(level string) (string, widget.Importance, fyne.ThemeColorName, fyne.Resource) {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "VULN":
		return "已验证 · POC 命中", widget.SuccessImportance, theme.ColorNameSuccess, theme.ConfirmIcon()
	case "SAFE":
		return "验证完成 · 未命中", widget.LowImportance, theme.ColorNameDisabled, theme.InfoIcon()
	case "CANCEL":
		return "验证中止 · 已取消", widget.WarningImportance, theme.ColorNameWarning, theme.MediaStopIcon()
	default:
		return "验证异常 · 执行错误", widget.DangerImportance, theme.ColorNameError, theme.ErrorIcon()
	}
}

func resultVerdict(result ExploitResult) string {
	switch strings.ToUpper(strings.TrimSpace(result.Level)) {
	case "VULN":
		return "判定结论：规则成立，目标呈现对应漏洞特征"
	case "SAFE":
		return "判定结论：规则未成立，当前请求未发现对应特征"
	case "CANCEL":
		return "判定结论：任务已取消，未形成完整验证结论"
	default:
		return "判定结论：执行异常，请检查网络、请求或匹配规则"
	}
}

func resultEvidenceHeadline(result ExploitResult) string {
	if result.Evidence != nil {
		if line := firstNonEmptyLine(result.Evidence.MatchEvidence); line != "" {
			return line
		}
	}
	if line := firstNonEmptyLine(result.Message); line != "" {
		return line
	}
	return "暂无额外证据"
}

func firstNonEmptyLine(value string) string {
	for _, line := range strings.Split(value, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func formatCompactBytes(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	if size < 1024*1024 {
		return fmt.Sprintf("%.1f KiB", float64(size)/1024)
	}
	return fmt.Sprintf("%.1f MiB", float64(size)/(1024*1024))
}
