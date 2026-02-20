#!/bin/bash
# 测试 antigravity 类型账号的 access_token 是否可用
#
# 用法:
#   ./test_antigravity_tokens.sh              # 扫描所有账号，标记异常账号到失败列表
#   ./test_antigravity_tokens.sh -a           # 扫描所有账号（包括已禁用的）
#   ./test_antigravity_tokens.sh -f           # 仅测试失败列表中的账号（逐个，遇 403 停止）
#   ./test_antigravity_tokens.sh -e EMAIL     # 仅测试指定邮箱的账号

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUTHS_DIR="$SCRIPT_DIR/auths"
API_URL="https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
MODEL="claude-sonnet-4-6"
USER_AGENT="antigravity/1.104.0 darwin/arm64"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# 文件路径
REPORT_FILE="$SCRIPT_DIR/antigravity_error_report.txt"
FAILED_LIST="$SCRIPT_DIR/antigravity_failed_accounts.txt"

# 解析参数
MODE="scan"       # scan=全量扫描并标记, failed=仅测试失败列表, single=单个账号
TARGET_EMAIL=""
INCLUDE_DISABLED=false

while getopts "afe:" opt; do
    case $opt in
        a) INCLUDE_DISABLED=true ;;
        f) MODE="failed" ;;
        e) MODE="single"; TARGET_EMAIL="$OPTARG" ;;
        *) echo "用法: $0 [-a] [-f] [-e email]"; exit 1 ;;
    esac
done

# 发送测试请求，返回 "HTTP状态码" 并将响应体写入临时文件
test_account() {
    local auth_file="$1"
    local email=$(jq -r '.email // "unknown"' "$auth_file")
    local access_token=$(jq -r '.access_token // ""' "$auth_file")
    local project_id=$(jq -r '.project_id // ""' "$auth_file")

    if [ -z "$access_token" ]; then
        echo -e "${RED}[异常]${NC} $email - access_token 为空"
        return 1
    fi

    local req_body=$(jq -n \
        --arg model "$MODEL" \
        --arg project "$project_id" \
        '{
            model: $model,
            request: {
                contents: [{role: "user", parts: [{text: "hi"}]}],
                generationConfig: {temperature: 1, maxOutputTokens: 32}
            },
            userAgent: "antigravity",
            requestType: "agent",
            project: $project
        }')

    local response=$(curl -s -w "\n%{http_code}" --max-time 15 \
        "$API_URL" \
        -H "authorization: Bearer $access_token" \
        -H "content-type: application/json" \
        -H "user-agent: $USER_AGENT" \
        -H "accept: text/event-stream" \
        -d "$req_body" 2>&1)

    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')

    if [ "$http_code" = "200" ]; then
        echo -e "${GREEN}[正常]${NC} $email (HTTP $http_code)"
        return 0
    else
        local formatted_body=$(echo "$body" | jq '.' 2>/dev/null || echo "$body")
        echo -e "${RED}[异常]${NC} $email (HTTP $http_code)"
        echo "$formatted_body"
        echo ""
        # 写入报告文件
        {
            echo "========================================"
            echo "账号: $email"
            echo "HTTP 状态码: $http_code"
            echo "响应内容:"
            echo "$formatted_body"
            echo ""
        } >> "$REPORT_FILE"

        if [ "$http_code" = "403" ]; then
            # 区分 VALIDATION_REQUIRED（需要停止）和账号封禁（直接标记跳过）
            local reason=$(echo "$body" | jq -r '.error.details[]? | select(.reason) | .reason' 2>/dev/null)
            if [ "$reason" = "VALIDATION_REQUIRED" ]; then
                return 2  # 需要验证，停止后续请求
            fi
            return 3  # 账号封禁等其他 403，继续扫描
        fi
        return 1
    fi
}

# 根据 email 查找对应的 auth 文件
find_auth_file() {
    local target_email="$1"
    for f in "$AUTHS_DIR"/*.json; do
        [ -f "$f" ] || continue
        local t=$(jq -r '.type // ""' "$f")
        [ "$t" != "antigravity" ] && continue
        local e=$(jq -r '.email // ""' "$f")
        if [ "$e" = "$target_email" ]; then
            echo "$f"
            return 0
        fi
    done
    return 1
}

# ==================== 模式: 全量扫描并标记 ====================
if [ "$MODE" = "scan" ]; then
    > "$REPORT_FILE"
    > "$FAILED_LIST"

    total=0; success=0; failed=0; skipped=0

    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  Antigravity Token 可用性扫描${NC}"
    echo -e "${CYAN}  (仅标记，不获取 validation_url)${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""

    for auth_file in "$AUTHS_DIR"/*.json; do
        [ -f "$auth_file" ] || continue

        token_type=$(jq -r '.type // ""' "$auth_file")
        [ "$token_type" != "antigravity" ] && continue

        email=$(jq -r '.email // "unknown"' "$auth_file")
        disabled=$(jq -r '.disabled // false' "$auth_file")
        total=$((total + 1))

        if [ "$disabled" = "true" ] && [ "$INCLUDE_DISABLED" = "false" ]; then
            echo -e "${YELLOW}[跳过]${NC} $email (已禁用)"
            skipped=$((skipped + 1))
            continue
        fi

        test_account "$auth_file"
        ret=$?

        if [ $ret -eq 0 ]; then
            success=$((success + 1))
        else
            failed=$((failed + 1))
            echo "$email" >> "$FAILED_LIST"
            if [ $ret -eq 2 ]; then
                echo -e "${YELLOW}检测到 403，停止后续请求以保护 validation_url${NC}"
                # 把剩余未测试的非禁用 antigravity 账号也加入失败列表
                found_current=false
                for remaining in "$AUTHS_DIR"/*.json; do
                    [ -f "$remaining" ] || continue
                    rt=$(jq -r '.type // ""' "$remaining")
                    [ "$rt" != "antigravity" ] && continue
                    re=$(jq -r '.email // ""' "$remaining")
                    rd=$(jq -r '.disabled // false' "$remaining")
                    [ "$rd" = "true" ] && [ "$INCLUDE_DISABLED" = "false" ] && continue
                    # 跳过已处理的账号（在当前文件之前和当前文件）
                    if [ "$remaining" = "$auth_file" ]; then
                        found_current=true
                        continue
                    fi
                    $found_current && echo "$re" >> "$FAILED_LIST"
                done
                break
            fi
        fi
    done

    # 去重失败列表
    if [ -f "$FAILED_LIST" ]; then
        sort -u "$FAILED_LIST" -o "$FAILED_LIST"
    fi

    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  扫描结果汇总${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "  总计: $total 个账号"
    echo -e "  ${GREEN}正常: $success${NC}"
    echo -e "  ${RED}异常: $failed${NC}"
    echo -e "  ${YELLOW}跳过: $skipped${NC} (已禁用)"

    if [ -s "$FAILED_LIST" ]; then
        fail_count=$(wc -l < "$FAILED_LIST" | tr -d ' ')
        echo ""
        echo -e "  失败账号列表 (${RED}${fail_count}${NC} 个):"
        while IFS= read -r line; do
            echo -e "    ${RED}*${NC} $line"
        done < "$FAILED_LIST"
        echo ""
        echo -e "  列表已保存至: ${CYAN}$FAILED_LIST${NC}"
        echo -e "  使用 ${CYAN}$0 -f${NC} 逐个测试失败账号获取 validation_url"
    fi
    echo ""

# ==================== 模式: 仅测试失败列表 ====================
elif [ "$MODE" = "failed" ]; then
    if [ ! -s "$FAILED_LIST" ]; then
        echo -e "${GREEN}失败列表为空，无需测试${NC}"
        echo -e "先运行 ${CYAN}$0${NC} 进行全量扫描"
        exit 0
    fi

    > "$REPORT_FILE"
    email=$(head -n1 "$FAILED_LIST")

    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  测试失败账号: $email${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""

    auth_file=$(find_auth_file "$email")
    if [ -z "$auth_file" ]; then
        echo -e "${RED}未找到账号 $email 的配置文件${NC}"
        # 从列表中移除
        sed -i '' '1d' "$FAILED_LIST"
        exit 1
    fi

    test_account "$auth_file"
    ret=$?

    if [ $ret -eq 0 ]; then
        echo -e "${GREEN}账号已恢复正常，从失败列表中移除${NC}"
    fi

    # 无论成功还是失败，都从列表中移除当前账号（已处理）
    sed -i '' '1d' "$FAILED_LIST"

    remaining=$(wc -l < "$FAILED_LIST" 2>/dev/null | tr -d ' ')
    echo ""
    if [ "$remaining" -gt 0 ] 2>/dev/null; then
        next=$(head -n1 "$FAILED_LIST")
        echo -e "  剩余 ${YELLOW}${remaining}${NC} 个待处理账号，下一个: ${CYAN}$next${NC}"
        echo -e "  处理完当前 validation_url 后，运行 ${CYAN}$0 -f${NC} 继续"
    else
        echo -e "${GREEN}所有失败账号已处理完毕${NC}"
    fi
    echo ""

# ==================== 模式: 单个账号 ====================
elif [ "$MODE" = "single" ]; then
    > "$REPORT_FILE"

    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  测试指定账号: $TARGET_EMAIL${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""

    auth_file=$(find_auth_file "$TARGET_EMAIL")
    if [ -z "$auth_file" ]; then
        echo -e "${RED}未找到账号 $TARGET_EMAIL 的配置文件${NC}"
        exit 1
    fi

    test_account "$auth_file"
    echo ""
fi
