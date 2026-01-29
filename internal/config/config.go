package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DataDir string     `yaml:"data_dir"`
	HTTP    HTTPConfig `yaml:"http"`
	SMTP    SMTPConfig `yaml:"smtp"`
	IMAP    IMAPConfig `yaml:"imap"`
	DKIM    DKIMConfig `yaml:"dkim"`
	API     APIConfig  `yaml:"api"`
	TLS     TLSConfig  `yaml:"tls"`
}

type HTTPConfig struct {
	Addr string `yaml:"addr"`
}

type APIConfig struct {
	Key string `yaml:"key"`
}

type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type SMTPConfig struct {
	Addr            string `yaml:"addr"`
	Domain          string `yaml:"domain"`
	MaxMessageBytes int64  `yaml:"max_message_bytes"`
	MaxRecipients   int    `yaml:"max_recipients"`
	AllowInsecure   bool   `yaml:"allow_insecure"`
}

type IMAPConfig struct {
	Addr          string `yaml:"addr"`
	AllowInsecure bool   `yaml:"allow_insecure"`
}

type DKIMConfig struct {
	Selector   string `yaml:"selector"`
	KeyBits    int    `yaml:"key_bits"`
	PrivateKey string `yaml:"private_key_path"`
}

// Default returns a config with sensible defaults
func Default() *Config {
	return &Config{
		DataDir: "./data",
		HTTP: HTTPConfig{
			Addr: ":8080",
		},
		SMTP: SMTPConfig{
			Addr:            ":2525",
			Domain:          "localhost",
			MaxMessageBytes: 50 * 1024 * 1024, // 50MB
			MaxRecipients:   50,
			AllowInsecure:   true,
		},
		IMAP: IMAPConfig{
			Addr:          ":1143",
			AllowInsecure: true,
		},
		DKIM: DKIMConfig{
			Selector: "default",
			KeyBits:  2048,
		},
	}
}

// Load reads config from a YAML file, falling back to defaults
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // Use defaults if no config file
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Save writes the config to a YAML file
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
