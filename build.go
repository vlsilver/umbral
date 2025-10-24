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

	fmt.Println("Building Rust library...")

	// Build Rust library
	cmd := exec.Command("cargo", "build", "--release", "--features", "bindings-c")
	cmd.Dir = filepath.Join(parentDir, "umbral-pre")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Fatal("Failed to build Rust library:", err)
	}

	fmt.Println("Rust library built successfully!")
}
