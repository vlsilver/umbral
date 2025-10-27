package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func main() {
	fmt.Println("🔧 Installing umbral-pre-cgo dependencies...")

	// Get the module cache directory
	cmd := exec.Command("go", "env", "GOMODCACHE")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("❌ Failed to get GOMODCACHE: %v\n", err)
		os.Exit(1)
	}

	modCache := string(output[:len(output)-1]) // Remove newline
	fmt.Printf("📁 Module cache: %s\n", modCache)

	// Find the umbral-pre-cgo module directory
	umbralDir := filepath.Join(modCache, "github.com", "vlsilver", "umbral", "umbral-pre-cgo@v0.11.4-go")
	if _, err := os.Stat(umbralDir); os.IsNotExist(err) {
		fmt.Printf("❌ Module directory not found: %s\n", umbralDir)
		fmt.Println("💡 Please run: go get github.com/vlsilver/umbral/umbral-pre-cgo")
		os.Exit(1)
	}

	fmt.Printf("📦 Found module directory: %s\n", umbralDir)

	// Create lib directory
	libDir := filepath.Join(umbralDir, "lib")
	if err := os.MkdirAll(libDir, 0755); err != nil {
		fmt.Printf("❌ Failed to create lib directory: %v\n", err)
		os.Exit(1)
	}

	// Determine library name
	var libName string
	switch runtime.GOOS {
	case "windows":
		libName = "libumbral_pre.dll"
	case "darwin":
		libName = "libumbral_pre.dylib"
	case "linux":
		libName = "libumbral_pre.so"
	default:
		fmt.Printf("❌ Unsupported platform: %s\n", runtime.GOOS)
		os.Exit(1)
	}

	libPath := filepath.Join(libDir, libName)

	// Check if library already exists
	if _, err := os.Stat(libPath); err == nil {
		fmt.Printf("✅ Library %s already exists\n", libName)
		fmt.Println("🎉 Installation complete!")
		return
	}

	// Download library from GitHub Releases
	fmt.Printf("📥 Downloading %s...\n", libName)
	downloadURL := fmt.Sprintf("https://github.com/vlsilver/umbral/releases/download/v0.11.4-go/%s", libName)

	cmd = exec.Command("curl", "-L", "-o", libPath, downloadURL)
	if err := cmd.Run(); err != nil {
		fmt.Printf("❌ Failed to download library: %v\n", err)
		fmt.Println("💡 Please try manual installation:")
		fmt.Println("   go run github.com/vlsilver/umbral/install-libs.go")
		os.Exit(1)
	}

	fmt.Printf("✅ Successfully downloaded %s\n", libName)
	fmt.Println("🎉 Installation complete!")
	fmt.Println("💡 You can now use: go get github.com/vlsilver/umbral/umbral-pre-cgo")
}
