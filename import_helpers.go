package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func parseTargets(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	replacer := strings.NewReplacer(";", "\n", ",", "\n", "\t", "\n")
	raw = replacer.Replace(raw)

	seen := map[string]struct{}{}
	targets := make([]string, 0)
	for _, line := range strings.Split(raw, "\n") {
		item := strings.TrimSpace(line)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		targets = append(targets, item)
	}
	return targets
}

func loadTargetsFromFile(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	targets := parseTargets(string(content))
	if len(targets) == 0 {
		return nil, fmt.Errorf("目标文件中未解析到有效地址")
	}
	return targets, nil
}

func importNucleiTemplatesFromDir(dir string) (string, []POC, error) {
	entries := make([]string, 0)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == ".yaml" || ext == ".yml" {
			entries = append(entries, path)
		}
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	if len(entries) == 0 {
		return "", nil, fmt.Errorf("目录中未找到 yaml/yml 模板")
	}
	sort.Strings(entries)

	all := make([]POC, 0)
	for _, path := range entries {
		file, openErr := os.Open(path)
		if openErr != nil {
			continue
		}
		_, pocs, importErr := importNucleiTemplate(file)
		_ = file.Close()
		if importErr != nil || len(pocs) == 0 {
			continue
		}

		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			rel = filepath.Base(path)
		}
		namePrefix := strings.TrimSuffix(rel, filepath.Ext(rel))
		namePrefix = strings.ReplaceAll(namePrefix, string(filepath.Separator), " / ")
		for i := range pocs {
			pocs[i].Name = fmt.Sprintf("%s :: %s", namePrefix, pocs[i].Name)
		}
		all = append(all, pocs...)
	}
	if len(all) == 0 {
		return "", nil, fmt.Errorf("未成功导入任何模板，可能模板格式不受支持")
	}

	folderName := fmt.Sprintf("Nuclei 批量导入 (%s)", filepath.Base(dir))
	return folderName, all, nil
}
