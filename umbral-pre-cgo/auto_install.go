package umbralprecgo

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
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

var (
	libDownloaded bool
	libMutex      sync.Mutex
)

func init() {
	// Auto-download library on package import (synchronous)
	ensureLibrary()
}

func ensureLibrary() {
	libMutex.Lock()
	defer libMutex.Unlock()

	if libDownloaded {
		return
	}

	libDir := "lib"
	libPath := filepath.Join(libDir, getLibraryName())

	// Check if library already exists
	if _, err := os.Stat(libPath); err == nil {
		libDownloaded = true
		return
	}

	// Download library
	if err := downloadLibrary(); err != nil {
		fmt.Printf("Warning: Failed to auto-download library: %v\n", err)
		fmt.Println("Please run: go run github.com/vlsilver/umbral/install-libs.go")
		return
	}

	libDownloaded = true
}

func getLibraryName() string {
	switch runtime.GOOS {
	case "windows":
		return "libumbral_pre.dll"
	case "darwin":
		return "libumbral_pre.dylib"
	case "linux":
		return "libumbral_pre.so"
	default:
		return ""
	}
}

func downloadLibrary() error {
	// Get latest release
	release, err := getLatestRelease()
	if err != nil {
		return fmt.Errorf("failed to get latest release: %v", err)
	}

	libName := getLibraryName()
	if libName == "" {
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
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
		return fmt.Errorf("library %s not found in release %s", libName, release.TagName)
	}

	// Create lib directory
	libDir := "lib"
	if err := os.MkdirAll(libDir, 0755); err != nil {
		return fmt.Errorf("failed to create lib directory: %v", err)
	}

	// Download library
	filePath := filepath.Join(libDir, libName)
	return downloadFile(downloadURL, filePath)
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
