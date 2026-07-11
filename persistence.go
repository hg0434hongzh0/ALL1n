package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const dataFileName = "poc_data.json"

func appDataFilePath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("获取用户配置目录失败: %w", err)
	}
	return filepath.Join(configDir, "ALL1n", dataFileName), nil
}

func loadAppData() (*appData, string, error) {
	path, err := appDataFilePath()
	if err != nil {
		path = dataFileName
	}

	data, loadErr := loadDataFromFile(path)
	if loadErr != nil || data != nil || path == dataFileName {
		return data, path, errors.Join(err, loadErr)
	}

	// Migrate data created by older versions in the working directory.
	legacyData, legacyErr := loadDataFromFile(dataFileName)
	if legacyErr != nil || legacyData == nil {
		return nil, path, errors.Join(err, legacyErr)
	}
	if saveErr := saveDataToFile(path, legacyData); saveErr != nil {
		return legacyData, path, fmt.Errorf("迁移旧数据失败: %w", saveErr)
	}
	return legacyData, path, nil
}
func saveDataToFile(path string, data *appData) error {
	if data == nil {
		return fmt.Errorf("数据为空")
	}
	if path == "" {
		return fmt.Errorf("保存路径为空")
	}

	data.ensure()
	if err := data.validate(); err != nil {
		return err
	}

	payload, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建数据目录失败: %w", err)
	}

	tempFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tempPath := tempFile.Name()
	committed := false
	defer func() {
		_ = tempFile.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()

	if _, err := tempFile.Write(payload); err != nil {
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("同步临时文件失败: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("关闭临时文件失败: %w", err)
	}

	if err := replaceFile(tempPath, path); err != nil {
		return fmt.Errorf("替换数据文件失败: %w", err)
	}
	committed = true
	return nil
}

// replaceFile uses a backup so repeated saves work on Windows, where Rename
// cannot replace an existing destination file.
func replaceFile(source, destination string) error {
	backup := destination + ".bak"
	_ = os.Remove(backup)

	_, statErr := os.Stat(destination)
	destinationExists := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return statErr
	}

	if destinationExists {
		if err := os.Rename(destination, backup); err != nil {
			return err
		}
	}

	if err := os.Rename(source, destination); err != nil {
		if destinationExists {
			_ = os.Rename(backup, destination)
		}
		return err
	}

	if destinationExists {
		_ = os.Remove(backup)
	}
	return nil
}

func loadDataFromFile(path string) (*appData, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		backupPath := path + ".bak"
		payload, err = os.ReadFile(backupPath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("读取数据备份失败: %w", err)
		}
		// Best-effort recovery after an interrupted replacement.
		_ = os.Rename(backupPath, path)
	}

	var data appData
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, err
	}

	data.ensure()
	if err := data.validate(); err != nil {
		return nil, err
	}

	return &data, nil
}

func exportData(writer io.Writer, data *appData) error {
	if data == nil {
		return fmt.Errorf("数据为空")
	}

	data.ensure()
	if err := data.validate(); err != nil {
		return err
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func importData(reader io.Reader) (*appData, error) {
	decoder := json.NewDecoder(reader)

	var data appData
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("JSON 文件只能包含一个数据对象")
		}
		return nil, fmt.Errorf("JSON 尾部存在无效内容: %w", err)
	}

	data.ensure()
	if err := data.validate(); err != nil {
		return nil, err
	}

	return &data, nil
}
