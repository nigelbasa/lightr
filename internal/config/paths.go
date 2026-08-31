package config

import (
	"os"
	"path/filepath"
	"runtime"
)

type DefaultPathSet struct {
	ConfigPath string
	DataDir    string
	LogFile    string
	TLSCert    string
	TLSKey     string
}

func PlatformDefaults() DefaultPathSet {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("PROGRAMDATA")
		if base == "" {
			base = `C:\ProgramData`
		}
		root := filepath.Join(base, "Lightr")
		dataDir := filepath.Join(root, "data")
		tlsDir := filepath.Join(dataDir, "tls")
		return DefaultPathSet{
			ConfigPath: filepath.Join(root, "config.yaml"),
			DataDir:    dataDir,
			LogFile:    filepath.Join(root, "logs", "lightr.log"),
			TLSCert:    filepath.Join(tlsDir, "server.crt"),
			TLSKey:     filepath.Join(tlsDir, "server.key"),
		}
	default:
		dataDir := "/var/lib/lightr"
		tlsDir := filepath.Join(dataDir, "tls")
		return DefaultPathSet{
			ConfigPath: "/etc/lightr/config.yaml",
			DataDir:    dataDir,
			LogFile:    "/var/log/lightr/lightr.log",
			TLSCert:    filepath.Join(tlsDir, "server.crt"),
			TLSKey:     filepath.Join(tlsDir, "server.key"),
		}
	}
}
