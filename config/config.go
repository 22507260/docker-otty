package config

import (
	"gopkg.in/yaml.v3"
	"os"
)

type Config struct {
	TrivyURL                string   `yaml:"trivy_url"`
	ScanImages              []string `yaml:"scan_images"`
	ScanInstalledContainers bool     `yaml:"scan_installed_containers"`
	ScanRunningContainers   bool     `yaml:"scan_running_containers"`
	Interval                int      `yaml:"interval"`
	OutputDir               string   `yaml:"output_dir"`
}

func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cfg Config
	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
