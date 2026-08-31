package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadNormalizesLegacyAdminKeyAndDatabasePath(t *testing.T) {
	cfg := Default()
	cfg.API.AdminKey = "legacy"
	cfg.API.Key = ""
	cfg.Database = DatabaseConfig{}
	cfg.DataDir = "./state"

	cfg.normalize()

	if cfg.API.Key != "legacy" {
		t.Fatalf("expected admin key to backfill api key, got %q", cfg.API.Key)
	}
	if cfg.Database.Driver != DatabaseDriverSQLite {
		t.Fatalf("expected sqlite driver, got %q", cfg.Database.Driver)
	}
	if cfg.Database.Path != filepath.Join("state", "lightr.db") {
		t.Fatalf("expected derived sqlite path, got %q", cfg.Database.Path)
	}
}

func TestSMTPGreetingHostnamePrefersLegacyOverrideButDefaultsToServerHostname(t *testing.T) {
	cfg := Default()
	cfg.Server.Hostname = "mail.example.test"

	if got := cfg.SMTPGreetingHostname(); got != "mail.example.test" {
		t.Fatalf("SMTPGreetingHostname() = %q, want %q", got, "mail.example.test")
	}

	cfg.SMTP.Domain = "legacy.example.test"
	if got := cfg.SMTPGreetingHostname(); got != "legacy.example.test" {
		t.Fatalf("SMTPGreetingHostname() with legacy override = %q, want %q", got, "legacy.example.test")
	}
	if !cfg.HasLegacySMTPDomainOverride() {
		t.Fatalf("HasLegacySMTPDomainOverride() = false, want true")
	}
}

func TestValidateDatabaseConfig(t *testing.T) {
	cases := []struct {
		name    string
		cfg     DatabaseConfig
		wantErr bool
	}{
		{
			name: "sqlite",
			cfg: DatabaseConfig{
				Driver: DatabaseDriverSQLite,
				Path:   "./data/lightr.db",
			},
		},
		{
			name: "postgres missing dsn",
			cfg: DatabaseConfig{
				Driver: DatabaseDriverPostgres,
			},
			wantErr: true,
		},
		{
			name: "unsupported driver",
			cfg: DatabaseConfig{
				Driver: "mongodb",
				DSN:    "mongodb://localhost:27017",
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Database = tc.cfg
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected validation error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestSpamDefaultsAndNormalization(t *testing.T) {
	cfg := Default()
	cfg.Spam = SpamConfig{
		Enabled:             true,
		SuspiciousThreshold: 3,
		JunkThreshold:       2,
	}

	cfg.normalize()

	if cfg.Spam.TimeoutSeconds != 5 {
		t.Fatalf("expected spam timeout default 5, got %d", cfg.Spam.TimeoutSeconds)
	}
	if cfg.Spam.JunkThreshold != 3 {
		t.Fatalf("expected junk threshold normalized up to suspicious threshold, got %v", cfg.Spam.JunkThreshold)
	}
}

func TestDefaultUsesPlatformPaths(t *testing.T) {
	cfg := Default()
	paths := PlatformDefaults()

	if cfg.DataDir != paths.DataDir {
		t.Fatalf("DataDir = %q, want %q", cfg.DataDir, paths.DataDir)
	}
	if cfg.Database.Path != filepath.Join(paths.DataDir, "lightr.db") {
		t.Fatalf("Database.Path = %q", cfg.Database.Path)
	}
	if cfg.Logging.File != paths.LogFile {
		t.Fatalf("Logging.File = %q, want %q", cfg.Logging.File, paths.LogFile)
	}
	if cfg.TLS.CertFile != paths.TLSCert || cfg.TLS.KeyFile != paths.TLSKey {
		t.Fatalf("unexpected TLS default paths: cert=%q key=%q", cfg.TLS.CertFile, cfg.TLS.KeyFile)
	}
}

func TestRenderAnnotatedYAMLIncludesCommentedAlternativeDatabase(t *testing.T) {
	cfg := Default()
	cfg.Database.Driver = DatabaseDriverSQLite
	cfg.Database.Path = filepath.Join(cfg.DataDir, "lightr.db")

	rendered, err := RenderAnnotatedYAML(cfg)
	if err != nil {
		t.Fatalf("RenderAnnotatedYAML: %v", err)
	}

	if !strings.Contains(rendered, "driver: sqlite") {
		t.Fatalf("expected active sqlite driver in template, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "# dsn:") {
		t.Fatalf("expected commented postgres dsn in template, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "# Port guide:") {
		t.Fatalf("expected operator comments in template, got:\n%s", rendered)
	}
	if strings.Contains(rendered, "\n  domain:") || strings.Contains(rendered, "\n  # domain:") {
		t.Fatalf("expected smtp.domain to be absent from annotated template, got:\n%s", rendered)
	}
}
