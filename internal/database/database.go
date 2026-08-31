package database

import (
	"fmt"

	"github.com/nigelbasa/lightr/internal/config"
	"github.com/nigelbasa/lightr/internal/storage"
)

type Connector interface {
	Driver() config.DatabaseDriver
	Open(cfg config.DatabaseConfig) (*storage.SQLiteStore, error)
}

type Factory struct {
	connectors map[config.DatabaseDriver]Connector
}

func NewFactory(connectors ...Connector) *Factory {
	f := &Factory{
		connectors: map[config.DatabaseDriver]Connector{},
	}
	for _, connector := range connectors {
		if connector == nil {
			continue
		}
		f.connectors[connector.Driver()] = connector
	}
	return f
}

func DefaultFactory() *Factory {
	return NewFactory(
		SQLiteConnector{},
		PostgresConnector{},
	)
}

func (f *Factory) Open(cfg config.DatabaseConfig) (*storage.SQLiteStore, error) {
	connector, ok := f.connectors[cfg.Driver]
	if !ok {
		return nil, fmt.Errorf("no connector registered for %s", cfg.Driver)
	}
	return connector.Open(cfg)
}

type SQLiteConnector struct{}

func (SQLiteConnector) Driver() config.DatabaseDriver { return config.DatabaseDriverSQLite }

func (SQLiteConnector) Open(cfg config.DatabaseConfig) (*storage.SQLiteStore, error) {
	return storage.NewSQLiteStore(cfg.Path)
}

type PostgresConnector struct{}

func (PostgresConnector) Driver() config.DatabaseDriver { return config.DatabaseDriverPostgres }

func (PostgresConnector) Open(cfg config.DatabaseConfig) (*storage.SQLiteStore, error) {
	if cfg.DSN == "" {
		return nil, fmt.Errorf("database.dsn is required for postgres")
	}
	return storage.NewPostgresStore(cfg.DSN)
}
