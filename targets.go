package main

import (
	"bufio"
	"fmt"
	"strings"
)

const maxTargetCount = 1000

func parseTargets(raw string) ([]string, error) {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 1024*1024)

	targets := make([]string, 0, 16)
	seen := make(map[string]struct{})
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		value := strings.TrimSpace(scanner.Text())
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}

		normalized, err := buildTargetURL(value, "", "")
		if err != nil {
			return nil, fmt.Errorf("目标列表第 %d 行无效: %w", lineNumber, err)
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		targets = append(targets, normalized)
		if len(targets) > maxTargetCount {
			return nil, fmt.Errorf("单次最多允许 %d 个目标", maxTargetCount)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取目标列表失败: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("请至少输入一个有效目标")
	}
	return targets, nil
}
