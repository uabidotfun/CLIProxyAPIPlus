#!/bin/sh
# 容器启动入口脚本
# 功能: 在启动应用前，将 Surge CA 证书添加到系统信任存储

set -e

CERT_FILE="/usr/local/share/ca-certificates/surge-ca.crt"
SYSTEM_CERT_BUNDLE="/etc/ssl/certs/ca-certificates.crt"

# 检查证书文件是否存在
if [ -f "$CERT_FILE" ]; then
    echo "[Entrypoint] 检测到 Surge CA 证书，正在添加到系统信任存储..."
    
    # 检查证书是否已经存在于系统证书库中
    if ! grep -q "Surge Generated" "$SYSTEM_CERT_BUNDLE" 2>/dev/null; then
        # 直接追加到系统证书库（Alpine 兼容方式）
        cat "$CERT_FILE" >> "$SYSTEM_CERT_BUNDLE"
        echo "[Entrypoint] ✓ Surge CA 证书已追加到系统证书库"
    else
        echo "[Entrypoint] ✓ Surge CA 证书已存在于系统证书库中"
    fi
    
    # 同时在 /etc/ssl/certs/ 目录下创建符号链接（某些工具会直接扫描此目录）
    if [ ! -f "/etc/ssl/certs/surge-ca.crt" ]; then
        cp "$CERT_FILE" /etc/ssl/certs/surge-ca.crt
        echo "[Entrypoint] ✓ 证书已复制到 /etc/ssl/certs/"
    fi
else
    echo "[Entrypoint] 未检测到 Surge CA 证书，跳过证书配置"
fi

# 启动原应用
echo "[Entrypoint] 启动 CLIProxyAPIPlus..."
exec ./CLIProxyAPIPlus "$@"
