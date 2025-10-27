//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func main() {
	// Get the directory of this file
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)

	// Change to the parent directory (rust-umbral root)
	parentDir := filepath.Dir(dir)
	if err := os.Chdir(parentDir); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Building Rust library for all platforms...")

	// Build Rust library
	cmd := exec.Command("cargo", "build", "--release", "--features", "bindings-c")
	cmd.Dir = filepath.Join(parentDir, "umbral-pre")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Fatal("Failed to build Rust library:", err)
	}

	// Copy library to lib directory
	libDir := filepath.Join(dir, "lib")
	if err := os.MkdirAll(libDir, 0755); err != nil {
		log.Fatal("Failed to create lib directory:", err)
	}

	// Copy libraries for different platforms
	copyLibraryForPlatform(parentDir, libDir, runtime.GOOS)

	fmt.Println("Rust library built and copied successfully!")
}

func copyLibraryForPlatform(parentDir, libDir, goos string) {
	targetDir := filepath.Join(parentDir, "target", "release")

	var srcLib, dstLib string

	switch goos {
	case "darwin":
		srcLib = filepath.Join(targetDir, "libumbral_pre.dylib")
		dstLib = filepath.Join(libDir, "libumbral_pre.dylib")
	case "windows":
		srcLib = filepath.Join(targetDir, "umbral_pre.dll")
		dstLib = filepath.Join(libDir, "libumbral_pre.dll")
		// Also copy the import library
		srcLibImport := filepath.Join(targetDir, "umbral_pre.lib")
		dstLibImport := filepath.Join(libDir, "libumbral_pre.lib")
		copyFile(srcLibImport, dstLibImport)
	case "linux":
		srcLib = filepath.Join(targetDir, "libumbral_pre.so")
		dstLib = filepath.Join(libDir, "libumbral_pre.so")
	default:
		log.Printf("Warning: Unsupported platform %s", goos)
		return
	}

	copyFile(srcLib, dstLib)
}

func copyFile(src, dst string) {
	if _, err := os.Stat(src); os.IsNotExist(err) {
		log.Printf("Warning: Source file %s does not exist", src)
		return
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("copy", src, dst)
	} else {
		cmd = exec.Command("cp", src, dst)
	}

	if err := cmd.Run(); err != nil {
		log.Printf("Warning: Failed to copy %s to %s: %v", src, dst, err)
	} else {
		fmt.Printf("Copied library to %s\n", dst)
	}
}
