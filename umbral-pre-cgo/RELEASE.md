# Release Workflow

## For Repository Owner

### Automatic Release (GitHub Actions)
```bash
# Push to main branch triggers automatic build and release
git push origin main

# Or manually trigger workflow
# Go to GitHub Actions tab → "Build Pre-built Libraries" → "Run workflow"
```

### Manual Release (Development Only)
```bash
# 1. Clean everything
make clean-all

# 2. Build for local platform only
make build-rust

# 3. Test locally
make test
```

## For Users

### One Command Installation (Recommended)
```bash
go get github.com/vlsilver/umbral/umbral-pre-cgo
```

The package automatically downloads the required native library for your platform.

### Manual Installation (If Auto-download Fails)
```bash
# Build locally and install
go run github.com/vlsilver/umbral/umbral-pre-cgo/build.go
go get github.com/vlsilver/umbral/umbral-pre-cgo
```

## GitHub Actions Workflow

The `.github/workflows/build.yml` automatically:
1. ✅ Builds Rust library for all platforms (Windows, macOS, Linux)
2. ✅ Runs Go tests to ensure compatibility
3. ✅ Uploads artifacts for each platform
4. ✅ Creates GitHub Release with pre-built libraries
5. ✅ Triggers on push to main or manual dispatch

## Files Included

- `build.go` - Cross-platform build script (for local development)
- `install-libs.go` - Auto-installer for users (located in root directory)
- `.github/workflows/build.yml` - GitHub Actions workflow
- `Makefile` - Development build commands

