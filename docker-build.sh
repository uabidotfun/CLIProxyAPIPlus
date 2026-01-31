#!/usr/bin/env bash
#
# docker-build.sh - Docker 构建与启动脚本（开发者模式）
#
# 从源码构建本地镜像并启动，自动备份并恢复 usage 统计数据。
#
# 用法：
#   ./docker-build.sh              # 默认启用 usage 备份恢复
#   ./docker-build.sh --no-usage   # 禁用 usage 备份恢复
#
# 工作原理：
# - 首次运行会要求输入 Management API key，并写入 temp/stats/.api_secret
# - 重建前调用 /v0/management/usage/export 导出 usage 到 temp/stats/.usage_backup.json
# - 重建后调用 /v0/management/usage/import 再导回去
#
# 注意：
# - 本脚本默认通过 http://localhost:<port>/ 判断服务是否存活。
# - port 会从 config.yaml 的 "port:" 行读取；没有则默认 8317。

set -euo pipefail

# 保存 usage 备份与管理密钥的目录（不会被 git 跟踪）
STATS_DIR="temp/stats"
STATS_FILE="${STATS_DIR}/.usage_backup.json"
SECRET_FILE="${STATS_DIR}/.api_secret"
WITH_USAGE=true

# 从 config.yaml 提取端口号（用于拼接 Management API 的访问地址）
get_port() {
  if [[ -f "config.yaml" ]]; then
    # 这里用 grep+sed 做一个很轻量的解析：只要有类似 "port: 8317" 就能匹配
    grep -E "^port:" config.yaml | sed -E 's/^port: *["'"'"']?([0-9]+)["'"'"']?.*$/\1/'
  else
    echo "8317"
  fi
}

# 获取（或首次创建）用于访问 Management API 的密钥。
# - 若已有 temp/stats/.api_secret 则直接读取
# - 否则提示用户输入，并以 600 权限保存
export_stats_api_secret() {
  if [[ -f "${SECRET_FILE}" ]]; then
    API_SECRET=$(cat "${SECRET_FILE}")
  else
    if [[ ! -d "${STATS_DIR}" ]]; then
      mkdir -p "${STATS_DIR}"
    fi
    echo "首次使用 --with-usage，需要提供 Management API key。"
    read -r -p "请输入 management key: " -s API_SECRET
    echo
    echo "${API_SECRET}" > "${SECRET_FILE}"
    chmod 600 "${SECRET_FILE}"
  fi
}

# 检查服务是否已在本机端口上可用。
# 目的：导出 usage 前必须保证旧服务仍可响应 /（HTTP 200）。
check_container_running() {
  local port
  port=$(get_port)

  if ! curl -s -o /dev/null -w "%{http_code}" "http://localhost:${port}/" | grep -q "200"; then
    echo "错误：cli-proxy-api 服务未在 localhost:${port} 正常响应"
    echo "请先启动容器，或不要使用 --with-usage 参数。"
    exit 1
  fi
}

# 调用 Management API 导出 usage 统计。
export_stats() {
  local port
  port=$(get_port)

  if [[ ! -d "${STATS_DIR}" ]]; then
    mkdir -p "${STATS_DIR}"
  fi
  check_container_running

  echo "正在导出 usage 统计..."

  # curl 输出 body + 末尾追加一行 http code，便于脚本判断成功/失败
  EXPORT_RESPONSE=$(curl -s -w "\n%{http_code}" -H "X-Management-Key: ${API_SECRET}" \
    "http://localhost:${port}/v0/management/usage/export")

  HTTP_CODE=$(echo "${EXPORT_RESPONSE}" | tail -n1)
  RESPONSE_BODY=$(echo "${EXPORT_RESPONSE}" | sed '$d')

  if [[ "${HTTP_CODE}" != "200" ]]; then
    echo "导出失败（HTTP ${HTTP_CODE}）：${RESPONSE_BODY}"
    exit 1
  fi

  echo "${RESPONSE_BODY}" > "${STATS_FILE}"
  echo "已导出到：${STATS_FILE}"
}

# 调用 Management API 导入 usage 统计。
import_stats() {
  local port
  port=$(get_port)

  echo "正在导入 usage 统计..."

  IMPORT_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -H "X-Management-Key: ${API_SECRET}" \
    -H "Content-Type: application/json" \
    -d @"${STATS_FILE}" \
    "http://localhost:${port}/v0/management/usage/import")

  IMPORT_CODE=$(echo "${IMPORT_RESPONSE}" | tail -n1)
  IMPORT_BODY=$(echo "${IMPORT_RESPONSE}" | sed '$d')

  if [[ "${IMPORT_CODE}" == "200" ]]; then
    echo "导入成功"
  else
    echo "导入失败（HTTP ${IMPORT_CODE}）：${IMPORT_BODY}"
  fi

  # 导入后清理本地备份文件（避免下次误用旧数据）
  rm -f "${STATS_FILE}"
}

# 等待服务启动就绪（最多 30 秒）。
# 目的：重建容器后，需要等服务起来，才能调用 import。
wait_for_service() {
  local port
  port=$(get_port)

  echo "等待服务就绪..."
  for i in {1..30}; do
    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:${port}/" | grep -q "200"; then
      break
    fi
    sleep 1
  done

  # 额外等待一会，避免服务刚起但 Management API 还没 ready
  sleep 2
}

# --- 参数解析：--no-usage 禁用 usage 备份恢复 ---
if [[ "${1:-}" == "--no-usage" ]]; then
  WITH_USAGE=false
else
  export_stats_api_secret
fi

# --- 从源码构建并运行 ---
echo "--- 从源码构建并运行 ---"

# 生成版本信息（注入到 Docker build 的 ARG）
VERSION="$(git describe --tags --always --dirty)"
COMMIT="$(git rev-parse --short HEAD)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "本次构建信息："
echo "  Version: ${VERSION}"
echo "  Commit: ${COMMIT}"
echo "  Build Date: ${BUILD_DATE}"
echo "----------------------------------------"

# 用一个本地镜像名覆盖 compose 文件默认的远端镜像名，防止误拉远端镜像
export CLI_PROXY_IMAGE="cli-proxy-api:local"

echo "正在构建 Docker 镜像..."
docker compose build \
  --build-arg VERSION="${VERSION}" \
  --build-arg COMMIT="${COMMIT}" \
  --build-arg BUILD_DATE="${BUILD_DATE}"

# 如果要保留 usage，构建完成后、重建容器前导出
if [[ "${WITH_USAGE}" == "true" ]]; then
  export_stats
fi

echo "正在启动服务..."
# --pull never：不从远端拉取，强制使用本地刚 build 出来的镜像
docker compose up -d --remove-orphans --pull never

if [[ "${WITH_USAGE}" == "true" ]]; then
  wait_for_service
  import_stats
fi

echo "构建完成，服务已启动（使用本地镜像）。"
echo "可运行 'docker compose logs -f' 查看日志。"
