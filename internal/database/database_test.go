package database

import (
	"testing"

	"github.com/nigelbasa/lightr/internal/config"
)

func TestDefaultFactorySupportsSQLite(t *testing.T) {
	factory := DefaultFactory()
	store, err := factory.Open(config.DatabaseConfig{
		Driver: config.DatabaseDriverSQLite,
		Path:   t.TempDir() + "/lightr.db",
	})
	if err != nil {
		t.Fatalf("expected sqlite connector to open: %v", err)
	}
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("failed to close sqlite store: %v", err)
		}
	}()
}

func TestDefaultFactoryRejectsUnsupportedDriver(t *testing.T) {
	factory := DefaultFactory()
	_, err := factory.Open(config.DatabaseConfig{
		Driver: "mongodb",
		DSN:    "mongodb://localhost:27017",
	})
	if err == nil {
		t.Fatal("expected error for unsupported driver")
	}
}
