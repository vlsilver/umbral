@echo off
REM Simple Windows installer for umbral-pre-cgo
REM This script downloads pre-built libraries and installs the package

echo 🔧 Installing umbral-pre-cgo for Windows...
echo ==========================================

REM Create lib directory
if not exist "lib" mkdir "lib"

REM Download pre-built library
echo 📥 Downloading pre-built library...
powershell -Command "& {Invoke-WebRequest -Uri 'https://github.com/vlsilver/umbral/releases/download/v0.11.3-go/libumbral_pre.dll' -OutFile 'lib\libumbral_pre.dll'}"

if exist "lib\libumbral_pre.dll" (
    echo ✅ Library downloaded successfully!
    echo 🎉 You can now use: go get github.com/vlsilver/umbral/umbral-pre-cgo
) else (
    echo ❌ Failed to download library
    echo 💡 Please try manual build: go run build.go
    pause
    exit /b 1
)

pause
