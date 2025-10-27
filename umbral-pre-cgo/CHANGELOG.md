# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.11.4-go] - 2024-10-27

### Added
- **install-deps.go helper**: New script to install dependencies in module cache
- **Better Windows support**: Improved installation process for Windows users
- **Multiple fallback methods**: Enhanced installation options for different scenarios

### Fixed
- **Windows linker errors**: Resolved "cannot find -lumbral_pre" issues
- **Module cache installation**: Proper dependency installation in Go module cache
- **Cross-platform compatibility**: Better support for all platforms

### Changed
- **Installation documentation**: Updated README and WINDOWS.md with clearer instructions
- **Error handling**: Improved error messages and troubleshooting steps

## [v0.11.3-go] - 2024-10-27

### Added
- **Auto-install functionality**: Package now automatically downloads native libraries on import
- **One-command installation**: Users only need `go get github.com/vlsilver/umbral/umbral-pre-cgo`
- **GitHub Actions workflow**: Automated building and releasing of pre-built libraries
- **Cross-platform support**: Automatic detection and download of platform-specific libraries
- **Fallback mechanisms**: Manual installation options if auto-download fails

### Changed
- **Installation process**: Simplified from 2-step to 1-step process
- **Documentation**: Updated all docs to reflect single-command installation
- **Release workflow**: Moved to GitHub Actions for automated releases

### Fixed
- **Windows compatibility**: Proper handling of `.dll` and `.lib` files
- **Cross-platform builds**: Automated building for Windows, macOS, and Linux

## [v0.11.0-go] - 2024-10-25

### Added
- Initial release of Umbral Pre-Go
- Go bindings for Umbral Proxy Re-encryption library
- Ethereum key support with secp256k1 curve
- Complete E2E workflow implementation
- Automatic Rust library building
- Comprehensive test suite
- Docker support
- Makefile for build automation

### Features
- **Encryption**: Encrypt data with public keys
- **Re-encryption**: Create and use rekey fragments
- **Decryption**: Decrypt original and re-encrypted data
- **Ethereum Integration**: Full support for Ethereum key pairs
- **Byte Serialization**: Convert all objects to/from bytes
- **Stream Processing**: Support for large data streams

### Dependencies
- Based on umbral-pre v0.11.0
- Go 1.24.0+ required
- go-ethereum v1.16.5
- Rust toolchain for building

### Installation
```bash
go get github.com/vlsilver/umbral/umbral-pre-cgo
```

### Usage
```go
import "github.com/vlsilver/umbral/umbral-pre-cgo"

// Generate Ethereum keys
delegatingPrivateKey, delegatingPublicKey, err := umbralprecgo.GenerateEthereumKeyPair()

// Encrypt data
ciphertext, capsuleBytes, err := umbralprecgo.EncrypData(plaintext, delegatingPublicKey)

// Create rekey
kfragBytes, err := umbralprecgo.CreateRekey(delegatingPrivateKey, receivingPublicKey, 1)

// Re-encrypt
cfragBytes, err := umbralprecgo.ReencryptCapsule(capsuleBytes, kfragBytes, ...)

// Decrypt
decrypted, err := umbralprecgo.DecryptReencryptedData(ciphertext, cfragBytes, ...)
```
