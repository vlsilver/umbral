package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

const (
	apiURL  = "https://api.github.com/repos/vlsilver/umbral/releases/latest"
	baseURL = "https://github.com/vlsilver/umbral/releases/download"
)

type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

func main() {
	fmt.Println("🔧 Auto-installing pre-built libraries for umbral-pre-cgo...")

	// Get latest release
	release, err := getLatestRelease()
	if err != nil {
		fmt.Printf("❌ Failed to get latest release: %v\n", err)
		fmt.Println("💡 Please build manually using: go run build.go")
		os.Exit(1)
	}

	fmt.Printf("📦 Found latest release: %s\n", release.TagName)

	// Determine platform
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

	// Find the library in release assets
	var downloadURL string
	for _, asset := range release.Assets {
		if asset.Name == libName {
			downloadURL = asset.URL
			break
		}
	}

	if downloadURL == "" {
		fmt.Printf("❌ Library %s not found in release %s\n", libName, release.TagName)
		fmt.Println("💡 Please build manually using: go run build.go")
		os.Exit(1)
	}

	// Create lib directory
	libDir := "lib"
	if err := os.MkdirAll(libDir, 0755); err != nil {
		fmt.Printf("❌ Failed to create lib directory: %v\n", err)
		os.Exit(1)
	}

	// Download library
	filePath := filepath.Join(libDir, libName)

	fmt.Printf("📥 Downloading %s from %s\n", libName, downloadURL)

	if err := downloadFile(downloadURL, filePath); err != nil {
		fmt.Printf("❌ Failed to download library: %v\n", err)
		fmt.Println("💡 Please build manually using: go run build.go")
		os.Exit(1)
	}

	fmt.Printf("✅ Successfully installed %s\n", filePath)
	fmt.Println("🎉 You can now use: go get github.com/vlsilver/umbral/umbral-pre-cgo")
}

func getLatestRelease() (*Release, error) {
	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	return &release, nil
}

func downloadFile(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
