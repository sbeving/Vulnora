package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

// EnsureDir creates a directory if it doesn't exist
func EnsureDir(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0755)
	}
	return nil
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// GetFileSize returns the size of a file
func GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// GetConfigPath returns the path to the config file
func GetConfigPath(configFile string) string {
	if filepath.IsAbs(configFile) {
		return configFile
	}
	
	// Look in current directory first
	if FileExists(configFile) {
		return configFile
	}
	
	// Look in configs directory
	configPath := filepath.Join("configs", configFile)
	if FileExists(configPath) {
		return configPath
	}
	
	return configFile
}

// PrintBanner prints the application banner
func PrintBanner(appName, version string) {
	fmt.Printf(`
  _   _       _                 
 | | | |_ __ | |_ __   ___  _ __ 
 | | | | '_ \| | '_ \ / _ \| '__|
 | |_| | | | | | | | | (_) | |   
  \___/|_| |_|_|_| |_|\___/|_|   
                                
%s v%s - AI-Powered Security Testing Platform

`, appName, version)
}
