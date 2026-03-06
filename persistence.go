package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const dataFile = "poc_data.json"

func saveDataToFile(path string, data *appData) error {
	if data == nil {
		return fmt.Errorf("数据为空")
	}

	data.ensure()
	if err := data.validate(); err != nil {
		return err
	}

	payload, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, payload, 0o644); err != nil {
		return err
	}

	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	return nil
}

func loadDataFromFile(path string) (*appData, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
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

	data.ensure()
	if err := data.validate(); err != nil {
		return nil, err
	}

	return &data, nil
}
