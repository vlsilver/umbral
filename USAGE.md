# Umbral Pre-Go Library Usage Guide

## 📋 Overview

`umbral-pre-go` là một Go library cung cấp Proxy Re-encryption functionality sử dụng Umbral scheme với Ethereum keys.

## 🚀 Quick Start

### 1. Installation

```bash
# Clone repository
git clone https://github.com/nucypher/rust-umbral.git
cd rust-umbral/umbral-pre-cgo

# Build Rust library
cd ../umbral-pre
cargo build --release --features bindings-c

# Build Go library
cd ../umbral-pre-cgo
go mod tidy
go build
```

### 2. Basic Usage

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

## 🔧 API Reference

### Key Generation

#### `GenerateEthereumKeyPair() ([]byte, []byte, error)`
Tạo cặp khóa Ethereum mới.

**Returns:**
- `[]byte` - Private key bytes (32 bytes)
- `[]byte` - Public key bytes (33 bytes, compressed format)
- `error` - Error nếu có

**Example:**
```go
privateKey, publicKey, err := umbralprecgo.GenerateEthereumKeyPair()
```

### Encryption

#### `EncrypData(publicKeyBytes []byte, plaintext []byte) ([]byte, []byte, error)`
Mã hóa dữ liệu sử dụng public key.

**Parameters:**
- `publicKeyBytes` - Ethereum public key bytes (33 bytes)
- `plaintext` - Dữ liệu cần mã hóa

**Returns:**
- `[]byte` - Capsule bytes
- `[]byte` - Ciphertext
- `error` - Error nếu có

**Example:**
```go
capsuleBytes, ciphertext, err := umbralprecgo.EncrypData(publicKey, []byte("Hello World"))
```

### Rekey Creation

#### `CreateRekey(delegatingPrivateKeyBytes []byte, receivingPublicKeyBytes []byte) ([]byte, error)`
Tạo rekey fragments cho re-encryption.

**Parameters:**
- `delegatingPrivateKeyBytes` - Private key của delegating party (32 bytes)
- `receivingPublicKeyBytes` - Public key của receiving party (33 bytes)

**Returns:**
- `[]byte` - Key fragment bytes
- `error` - Error nếu có

**Example:**
```go
kfragBytes, err := umbralprecgo.CreateRekey(delegatingPrivateKey, receivingPublicKey)
```

### Re-encryption

#### `ReencryptCapsule(capsuleBytes []byte, kfragBytes []byte, verifyingPublicKeyBytes []byte, delegatingPublicKeyBytes []byte, receivingPublicKeyBytes []byte) ([]byte, error)`
Thực hiện re-encryption sử dụng key fragments.

**Parameters:**
- `capsuleBytes` - Capsule bytes từ encryption
- `kfragBytes` - Key fragment bytes từ CreateRekey
- `verifyingPublicKeyBytes` - Public key để verify key fragment
- `delegatingPublicKeyBytes` - Delegating public key
- `receivingPublicKeyBytes` - Receiving public key

**Returns:**
- `[]byte` - Capsule fragment bytes
- `error` - Error nếu có

**Example:**
```go
cfragBytes, err := umbralprecgo.ReencryptCapsule(
    capsuleBytes,
    kfragBytes,
    delegatingPublicKey, // verifying key
    delegatingPublicKey, // delegating key
    receivingPublicKey,  // receiving key
)
```

### Decryption

#### `DecryptReencryptedData(receivingPrivateKeyBytes []byte, delegatingPublicKeyBytes []byte, capsuleBytes []byte, cfragBytes []byte, ciphertext []byte) ([]byte, error)`
Giải mã dữ liệu đã được re-encrypted.

**Parameters:**
- `receivingPrivateKeyBytes` - Private key của receiving party (32 bytes)
- `delegatingPublicKeyBytes` - Public key của delegating party (33 bytes)
- `capsuleBytes` - Capsule bytes từ encryption
- `cfragBytes` - Capsule fragment bytes từ re-encryption
- `ciphertext` - Ciphertext từ encryption

**Returns:**
- `[]byte` - Decrypted plaintext
- `error` - Error nếu có

**Example:**
```go
decrypted, err := umbralprecgo.DecryptReencryptedData(
    receivingPrivateKey,
    delegatingPublicKey,
    capsuleBytes,
    cfragBytes,
    ciphertext,
)
```

## 🔄 Complete Workflow

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/vlsilver/umbral/umbral-pre-cgo"
)

func main() {
    // Step 1: Generate keys
    delegatingPrivateKey, delegatingPublicKey, err := umbralprecgo.GenerateEthereumKeyPair()
    if err != nil {
        log.Fatal(err)
    }
    
    receivingPrivateKey, receivingPublicKey, err := umbralprecgo.GenerateEthereumKeyPair()
    if err != nil {
        log.Fatal(err)
    }
    
    // Step 2: Encrypt data
    plaintext := []byte("Secret message")
    capsuleBytes, ciphertext, err := umbralprecgo.EncrypData(delegatingPublicKey, plaintext)
    if err != nil {
        log.Fatal(err)
    }
    
    // Step 3: Create rekey
    kfragBytes, err := umbralprecgo.CreateRekey(delegatingPrivateKey, receivingPublicKey)
    if err != nil {
        log.Fatal(err)
    }
    
    // Step 4: Re-encrypt
    cfragBytes, err := umbralprecgo.ReencryptCapsule(
        capsuleBytes,
        kfragBytes,
        delegatingPublicKey,
        delegatingPublicKey,
        receivingPublicKey,
    )
    if err != nil {
        log.Fatal(err)
    }
    
    // Step 5: Decrypt
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
    
    fmt.Printf("Original: %s\n", string(plaintext))
    fmt.Printf("Decrypted: %s\n", string(decrypted))
}
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

## 📦 Integration

### As a Go Module

```go
// go.mod
module your-project

go 1.21

require (
    github.com/vlsilver/umbral/umbral-pre-cgo v0.1.0
)
```

### Docker Integration

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

## ⚠️ Important Notes

1. **Memory Management**: Tất cả objects được tự động quản lý memory với `runtime.SetFinalizer`
2. **Key Format**: Sử dụng Ethereum keys (secp256k1 curve)
3. **Serialization**: Capsule và KeyFrag sử dụng `DefaultSerialize`/`DefaultDeserialize`
4. **Thread Safety**: Library không thread-safe, cần sync nếu sử dụng concurrent

## 🐛 Troubleshooting

### Common Issues

1. **Build Errors**:
   ```bash
   # Ensure Rust is installed
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   
   # Rebuild Rust library
   cd umbral-pre && cargo clean && cargo build --release --features bindings-c
   ```

2. **CGO Issues**:
   ```bash
   # Set CGO environment
   export CGO_ENABLED=1
   export CGO_LDFLAGS="-L$(pwd)/../target/release -lumbral_pre"
   ```

3. **Memory Issues**:
   - Đảm bảo gọi `Free()` methods khi cần
   - Sử dụng `defer` statements cho cleanup

## 📚 Examples

Xem thêm examples trong thư mục `examples/`:
- `examples/basic_usage.go` - Basic workflow
- `examples/multiple_messages.go` - Multiple messages
- `examples/validation.go` - Key validation

## 🤝 Contributing

1. Fork repository
2. Create feature branch
3. Make changes
4. Add tests
5. Submit pull request

## 📄 License

GPL-3.0-only
