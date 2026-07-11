package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const appVersion = "3.5.0"

type reportSummary struct {
	Total      int `json:"total"`
	Vulnerable int `json:"vulnerable"`
	Safe       int `json:"safe"`
	Errors     int `json:"errors"`
	Cancelled  int `json:"cancelled"`
}

type resultReport struct {
	Product    string          `json:"product"`
	Version    string          `json:"version"`
	ExportedAt time.Time       `json:"exported_at"`
	Summary    reportSummary   `json:"summary"`
	Results    []ExploitResult `json:"results"`
}

func summarizeResults(results []ExploitResult) reportSummary {
	summary := reportSummary{Total: len(results)}
	for _, result := range results {
		switch result.Level {
		case "VULN":
			summary.Vulnerable++
		case "SAFE":
			summary.Safe++
		case "CANCEL":
			summary.Cancelled++
		default:
			summary.Errors++
		}
	}
	return summary
}

func exportResultsJSON(writer io.Writer, results []ExploitResult) error {
	if len(results) == 0 {
		return fmt.Errorf("没有可导出的验证结果")
	}

	report := resultReport{
		Product:    "ALL1n POC Workbench",
		Version:    appVersion,
		ExportedAt: time.Now(),
		Summary:    summarizeResults(results),
		Results:    sanitizeResultsForExport(results),
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func exportResultsCSV(writer io.Writer, results []ExploitResult) error {
	if len(results) == 0 {
		return fmt.Errorf("没有可导出的验证结果")
	}

	// UTF-8 BOM keeps Chinese text readable when opened directly in Excel.
	if _, err := io.WriteString(writer, "\ufeff"); err != nil {
		return err
	}

	csvWriter := csv.NewWriter(writer)
	if err := csvWriter.Write([]string{
		"验证时间", "级别", "目标", "POC 名称", "请求方法", "URL", "HTTP 状态码",
		"耗时(ms)", "响应大小(bytes)", "响应已截断", "说明",
	}); err != nil {
		return err
	}

	for _, result := range sanitizeResultsForExport(results) {
		record := []string{
			result.TestedAt.Format(time.RFC3339),
			result.Level,
			safeSpreadsheetCell(result.Target),
			safeSpreadsheetCell(result.POCName),
			result.Method,
			safeSpreadsheetCell(result.URL),
			strconv.Itoa(result.StatusCode),
			strconv.FormatInt(result.Duration.Milliseconds(), 10),
			strconv.FormatInt(result.ResponseSize, 10),
			strconv.FormatBool(result.Truncated),
			safeSpreadsheetCell(result.Message),
		}
		if err := csvWriter.Write(record); err != nil {
			return err
		}
	}
	csvWriter.Flush()
	return csvWriter.Error()
}

func safeSpreadsheetCell(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed == "" {
		return value
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}
