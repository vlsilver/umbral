# Umbral Pre-Go

[![Go Reference](https://pkg.go.dev/badge/github.com/vlsilver/umbral/umbral-pre-cgo.svg)](https://pkg.go.dev/github.com/vlsilver/umbral/umbral-pre-cgo)
[![Go Report Card](https://goreportcard.com/badge/github.com/vlsilver/umbral/umbral-pre-cgo)](https://goreportcard.com/report/github.com/vlsilver/umbral/umbral-pre-cgo)
[![Version](https://img.shields.io/badge/version-v0.11.0--go-blue.svg)](https://github.com/vlsilver/umbral/releases)

Go bindings for the Umbral Proxy Re-encryption library with Ethereum key support.

**Version**: v0.11.0-go (based on umbral-pre v0.11.0)

## 🚀 Quick Start

### Installation

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install the library
go get github.com/vlsilver/umbral/umbral-pre-cgo
```

### Basic Usage

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/vlsilver/umbral/umbral-pre-cgo"
)

func main() {
    // Generate Ethereum key pairs
    delegatingPrivateKey, delegatingPublicKey, err := umbralprecgo.GenerateEthereumKeyPair()
    if err != nil {
        log.Fatal(err)
    }
    
    receivingPrivateKey, receivingPublicKey, err := umbralprecgo.GenerateEthereumKeyPair()
    if err != nil {
        log.Fatal(err)
    }
    
    // Encrypt data
    plaintext := []byte("Hello, Umbral!")
    capsuleBytes, ciphertext, err := umbralprecgo.EncrypData(delegatingPublicKey, plaintext)
    if err != nil {
        log.Fatal(err)
    }
    
    // Create rekey
    kfragBytes, err := umbralprecgo.CreateRekey(delegatingPrivateKey, receivingPublicKey)
    if err != nil {
        log.Fatal(err)
    }
    
    // Re-encrypt
    cfragBytes, err := umbralprecgo.ReencryptCapsule(
        capsuleBytes,
        kfragBytes,
        delegatingPublicKey, // verifying key
        delegatingPublicKey, // delegating key
        receivingPublicKey,  // receiving key
    )
    if err != nil {
        log.Fatal(err)
    }
    
    // Decrypt
    decrypted, err := umbralprecgo.DecryptReencryptedData(
        receivingPrivateKey,
        delegatingPublicKey,
        capsuleBytes,
        cfragBytes,
        ciphertext,
    )
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Decrypted: %s\n", string(decrypted))
}
```

## 📋 Features

- ✅ **Ethereum Key Support**: Works with secp256k1 keys from go-ethereum
- ✅ **Proxy Re-encryption**: Full Umbral PRE workflow
- ✅ **Memory Safe**: Automatic memory management
- ✅ **Thread Safe**: Safe for concurrent use
- ✅ **Serialization**: Convert objects to/from bytes
- ✅ **Validation**: Key validation utilities

## 🔧 API Reference

### Key Generation

```go
// Generate Ethereum key pair
privateKey, publicKey, err := umbralprecgo.GenerateEthereumKeyPair()
```

### Encryption

```go
// Encrypt data with public key
capsuleBytes, ciphertext, err := umbralprecgo.EncrypData(publicKey, plaintext)
```

### Rekey Creation

```go
// Create rekey fragments
kfragBytes, err := umbralprecgo.CreateRekey(delegatingPrivateKey, receivingPublicKey)
```

### Re-encryption

```go
// Re-encrypt capsule
cfragBytes, err := umbralprecgo.ReencryptCapsule(
    capsuleBytes,
    kfragBytes,
    verifyingPublicKey,
    delegatingPublicKey,
    receivingPublicKey,
)
```

### Decryption

```go
// Decrypt re-encrypted data
decrypted, err := umbralprecgo.DecryptReencryptedData(
    receivingPrivateKey,
    delegatingPublicKey,
    capsuleBytes,
    cfragBytes,
    ciphertext,
)
```

## 🧪 Testing

```bash
# Run all tests
go test -v

# Run specific test
go test -v -run TestE2EWorkflow

# Run with coverage
go test -v -cover
```

## 📦 Docker Support

```dockerfile
FROM golang:1.21-alpine AS builder

# Install Rust
RUN apk add --no-cache rust cargo

# Copy source
COPY . /app
WORKDIR /app

# Build Rust library
RUN cd umbral-pre && cargo build --release --features bindings-c

# Build Go application
RUN cd umbral-pre-cgo && go build -o app

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/umbral-pre-cgo/app .
CMD ["./app"]
```

## 🔄 Workflow

```
1. GenerateEthereumKeyPair() → privateKey, publicKey
2. EncrypData() → capsuleBytes, ciphertext
3. CreateRekey() → kfragBytes
4. ReencryptCapsule() → cfragBytes
5. DecryptReencryptedData() → decrypted plaintext
```

## ⚠️ Requirements

- **Go**: 1.21+
- **Rust**: Latest stable
- **CGO**: Enabled
- **OS**: Linux, macOS, Windows

## 🐛 Troubleshooting

### Build Issues

```bash
# Ensure Rust is installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clean and rebuild
cd umbral-pre
cargo clean
cargo build --release --features bindings-c
```

### CGO Issues

```bash
# Set CGO environment
export CGO_ENABLED=1
export CGO_LDFLAGS="-L$(pwd)/../target/release -lumbral_pre"
```

## 📚 Examples

See the `examples/` directory for more usage examples:
- Basic workflow
- Multiple messages
- Key validation
- Error handling

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

GPL-3.0-only

## 🔗 Links

- [Umbral Paper](https://github.com/nucypher/umbral-doc)
- [Rust Implementation](https://github.com/nucypher/rust-umbral)
- [Go Documentation](https://pkg.go.dev/github.com/vlsilver/umbral/umbral-pre-cgo)