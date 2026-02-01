#!/bin/bash
# 构建 cliproxy 二进制文件

set -e

# 自动版本：优先用 git tag，否则用 git describe 生成
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "dev")}"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUTPUT="cliproxy"

# 支持交叉编译
GOOS="${GOOS:-$(go env GOOS)}"
GOARCH="${GOARCH:-$(go env GOARCH)}"

if [[ "$GOOS" != "$(go env GOOS)" || "$GOARCH" != "$(go env GOARCH)" ]]; then
    OUTPUT="${OUTPUT}-${GOOS}-${GOARCH}"
fi

echo "Building ${OUTPUT}..."
echo "  Version: ${VERSION}"
echo "  Commit:  ${COMMIT}"
echo "  Date:    ${BUILD_DATE}"
echo "  OS/Arch: ${GOOS}/${GOARCH}"

GOOS=$GOOS GOARCH=$GOARCH go build \
    -ldflags="-s -w -X 'main.Version=${VERSION}' -X 'main.Commit=${COMMIT}' -X 'main.BuildDate=${BUILD_DATE}'" \
    -o "${OUTPUT}" \
    ./cmd/server/

echo "Done: ${OUTPUT}"

# 如果是本地构建且 launchd 服务正在运行，自动重启
if [[ "$GOOS" == "$(go env GOOS)" && "$GOARCH" == "$(go env GOARCH)" ]]; then
    if launchctl list | grep -q "com.cliproxy"; then
        echo "Restarting launchd service..."
        launchctl kickstart -k gui/$(id -u)/com.cliproxy
        echo "Service restarted."
    fi
fi
