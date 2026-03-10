#!/bin/bash
echo "开始编译多平台版本..."

# Windows
GOOS=windows GOARCH=amd64 go build -o HYDProxyBox-windows.exe main.go

# macOS Intel
GOOS=darwin GOARCH=amd64 go build -o HYDProxyBox-macos-amd64 main.go

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o HYDProxyBox-macos-arm64 main.go

# Linux
GOOS=linux GOARCH=amd64 go build -o HYDProxyBox-linux-amd64 main.go

echo "✅ 编译完成！文件在当前目录中"