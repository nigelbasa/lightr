package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DataDir  string         `yaml:"data_dir"`
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	HTTP     HTTPConfig     `yaml:"http"`
	SMTP     SMTPConfig     `yaml:"smtp"`
	IMAP     IMAPConfig     `yaml:"imap"`
	DKIM     DKIMConfig     `yaml:"dkim"`
	API      APIConfig      `yaml:"api"`
	TLS      TLSConfig      `yaml:"tls"`
	Webhook  WebhookConfig  `yaml:"webhook"`
	Logging  LoggingConfig  `yaml:"logging"`
	Spam     SpamConfig     `yaml:"spam"`
	Security SecurityConfig `yaml:"security"`
}

type WebhookConfig struct {
	URL     string `yaml:"url"` // Global webhook URL for all email events
	Enabled bool   `yaml:"enabled"`
}

type ServerConfig struct {
	Hostname    string `yaml:"hostname"`
	BindAddress string `yaml:"bind_address"`
}

type DatabaseDriver string

const (
	DatabaseDriverSQLite   DatabaseDriver = "sqlite"
	DatabaseDriverPostgres DatabaseDriver = "postgres"
)

type DatabaseConfig struct {
	Driver DatabaseDriver `yaml:"driver"`
	Path   string         `yaml:"path"`
	DSN    string         `yaml:"dsn"`
}

type HTTPConfig struct {
	Addr string `yaml:"addr"`
}

type APIConfig struct {
	Key      string `yaml:"key"`
	AdminKey string `yaml:"admin_key"`
}

type TLSConfig struct {
	CertFile    string                      `yaml:"cert_file"`    // Default cert
	KeyFile     string                      `yaml:"key_file"`     // Default key
	DomainCerts map[string]DomainCertConfig `yaml:"domain_certs"` // Per-domain certs for SNI
}

// DomainCertConfig holds TLS certificate paths for a specific domain
type DomainCertConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type SMTPConfig struct {
	Addr            string `yaml:"addr"`
	SubmissionAddr  string `yaml:"submission_addr"`  // Port 587
	Domain          string `yaml:"domain,omitempty"` // Deprecated: use server.hostname
	MaxMessageBytes int64  `yaml:"max_message_bytes"`
	MaxRecipients   int    `yaml:"max_recipients"`
	AllowInsecure   bool   `yaml:"allow_insecure"`
}

type IMAPConfig struct {
	Addr          string `yaml:"addr"`
	TLSAddr       string `yaml:"tls_addr"` // Port 993 (IMAPS)
	AllowInsecure bool   `yaml:"allow_insecure"`
}

type DKIMConfig struct {
	Selector   string `yaml:"selector"`
	KeyBits    int    `yaml:"key_bits"`
	PrivateKey string `yaml:"private_key_path"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

type SpamConfig struct {
	Enabled             bool     `yaml:"enabled"`
	SuspiciousThreshold float64  `yaml:"suspicious_threshold"`
	JunkThreshold       float64  `yaml:"junk_threshold"`
	DNSBLZones          []string `yaml:"dnsbl_zones"`
	RspamdURL           string   `yaml:"rspamd_url"`
	RspamdPassword      string   `yaml:"rspamd_password"`
	TimeoutSeconds      int      `yaml:"timeout_seconds"`
}

type SecurityConfig struct {
	RequireTLSForAuth bool `yaml:"require_tls_for_auth"`
}

// Default returns a config with sensible defaults
func Default() *Config {
	paths := PlatformDefaults()
	return &Config{
		DataDir: paths.DataDir,
		Server: ServerConfig{
			Hostname:    "localhost",
			BindAddress: "0.0.0.0",
		},
		Database: DatabaseConfig{
			Driver: DatabaseDriverSQLite,
			Path:   filepath.Join(paths.DataDir, "lightr.db"),
		},
		HTTP: HTTPConfig{
			Addr: ":8080",
		},
		SMTP: SMTPConfig{
			Addr:            ":25",
			SubmissionAddr:  ":587",
			MaxMessageBytes: 25 * 1024 * 1024, // 25MB — matches Gmail/Outlook/Yahoo
			MaxRecipients:   50,
			AllowInsecure:   false,
		},
		IMAP: IMAPConfig{
			Addr:          ":143",
			TLSAddr:       ":993",
			AllowInsecure: false,
		},
		DKIM: DKIMConfig{
			Selector: "default",
			KeyBits:  2048,
		},
		TLS: TLSConfig{
			CertFile: paths.TLSCert,
			KeyFile:  paths.TLSKey,
		},
		Logging: LoggingConfig{
			Level: "info",
			File:  paths.LogFile,
		},
		Spam: SpamConfig{
			Enabled:             true,
			SuspiciousThreshold: 2.0,
			JunkThreshold:       4.0,
			TimeoutSeconds:      5,
		},
		Security: SecurityConfig{
			RequireTLSForAuth: true,
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

	cfg.normalize()

	return cfg, nil
}

// Save writes the config to a YAML file
func (c *Config) Save(path string) error {
	c.normalize()
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func (c *Config) normalize() {
	if c.Server.Hostname == "" {
		if c.SMTP.Domain != "" {
			c.Server.Hostname = c.SMTP.Domain
		} else {
			c.Server.Hostname = "localhost"
		}
	}
	if c.Server.BindAddress == "" {
		c.Server.BindAddress = "0.0.0.0"
	}

	if c.Database.Driver == "" {
		c.Database.Driver = DatabaseDriverSQLite
	}
	if c.Database.Path == "" && c.Database.Driver == DatabaseDriverSQLite {
		if c.DataDir == "" {
			c.DataDir = PlatformDefaults().DataDir
		}
		c.Database.Path = filepath.Join(c.DataDir, "lightr.db")
	}

	if c.DataDir == "" && c.Database.Path != "" && c.Database.Driver == DatabaseDriverSQLite {
		c.DataDir = filepath.Dir(c.Database.Path)
	}
	if c.DataDir == "" {
		c.DataDir = PlatformDefaults().DataDir
	}

	if c.HTTP.Addr == "" && c.API.AdminKey != "" {
		c.HTTP.Addr = ":8080"
	}
	if c.HTTP.Addr == "" {
		c.HTTP.Addr = ":8080"
	}

	if c.API.Key == "" && c.API.AdminKey != "" {
		c.API.Key = c.API.AdminKey
	}
	if c.API.AdminKey == "" && c.API.Key != "" {
		c.API.AdminKey = c.API.Key
	}

	if c.SMTP.Addr == "" {
		c.SMTP.Addr = ":25"
	}
	if c.SMTP.SubmissionAddr == "" {
		c.SMTP.SubmissionAddr = ":587"
	}
	if c.SMTP.MaxMessageBytes == 0 {
		c.SMTP.MaxMessageBytes = 25 * 1024 * 1024
	}
	if c.SMTP.MaxRecipients == 0 {
		c.SMTP.MaxRecipients = 50
	}

	if c.IMAP.Addr == "" {
		c.IMAP.Addr = ":143"
	}
	if c.IMAP.TLSAddr == "" {
		c.IMAP.TLSAddr = ":993"
	}

	if c.DKIM.Selector == "" {
		c.DKIM.Selector = "default"
	}
	if c.DKIM.KeyBits == 0 {
		c.DKIM.KeyBits = 2048
	}

	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.File == "" {
		c.Logging.File = PlatformDefaults().LogFile
	}
	if c.TLS.CertFile == "" {
		c.TLS.CertFile = PlatformDefaults().TLSCert
	}
	if c.TLS.KeyFile == "" {
		c.TLS.KeyFile = PlatformDefaults().TLSKey
	}
	if c.Spam.SuspiciousThreshold == 0 {
		c.Spam.SuspiciousThreshold = 2.0
	}
	if c.Spam.JunkThreshold == 0 {
		c.Spam.JunkThreshold = 4.0
	}
	if c.Spam.TimeoutSeconds == 0 {
		c.Spam.TimeoutSeconds = 5
	}
	if c.Spam.JunkThreshold < c.Spam.SuspiciousThreshold {
		c.Spam.JunkThreshold = c.Spam.SuspiciousThreshold
	}

	if !c.Security.RequireTLSForAuth {
		// Preserve explicit insecure legacy settings while defaulting new configs to TLS.
		c.Security.RequireTLSForAuth = !(c.SMTP.AllowInsecure || c.IMAP.AllowInsecure)
	}

	c.Database.Driver = DatabaseDriver(strings.ToLower(string(c.Database.Driver)))
}

func (c *Config) NormalizeForSample() {
	c.normalize()
}

func (c *Config) SMTPGreetingHostname() string {
	if c == nil {
		return "localhost"
	}
	if strings.TrimSpace(c.SMTP.Domain) != "" {
		return strings.TrimSpace(c.SMTP.Domain)
	}
	if strings.TrimSpace(c.Server.Hostname) != "" {
		return strings.TrimSpace(c.Server.Hostname)
	}
	return "localhost"
}

func (c *Config) HasLegacySMTPDomainOverride() bool {
	return c != nil && strings.TrimSpace(c.SMTP.Domain) != ""
}

func (c *Config) Validate() error {
	switch c.Database.Driver {
	case DatabaseDriverSQLite:
		if c.Database.Path == "" {
			return fmt.Errorf("database.path is required for sqlite")
		}
	case DatabaseDriverPostgres:
		if c.Database.DSN == "" {
			return fmt.Errorf("database.dsn is required for postgres")
		}
	default:
		return fmt.Errorf("unsupported database driver %q (supported: sqlite, postgres)", c.Database.Driver)
	}
	if err := c.rejectPlaceholders(); err != nil {
		return err
	}
	return nil
}

// rejectPlaceholders fails fast when generated-config sentinels like CHANGE_ME
// are left in place. Keeps a misconfigured deployment from starting.
func (c *Config) rejectPlaceholders() error {
	const sentinel = "CHANGE_ME"
	check := func(field, value string) error {
		if strings.Contains(value, sentinel) {
			return fmt.Errorf("%s contains placeholder %q; replace with a real value", field, sentinel)
		}
		return nil
	}
	if err := check("database.dsn", c.Database.DSN); err != nil {
		return err
	}
	if err := check("spam.rspamd_password", c.Spam.RspamdPassword); err != nil {
		return err
	}
	if err := check("api.key", c.API.Key); err != nil {
		return err
	}
	return nil
}
