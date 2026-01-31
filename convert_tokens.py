#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
将 tokens_export.json 中的每个对象转换为单独的 JSON 文件
"""

import json
import os
from pathlib import Path


def camel_to_snake(name):
    """将 camelCase 转换为 snake_case"""
    result = []
    for i, char in enumerate(name):
        if char.isupper() and i > 0:
            result.append('_')
            result.append(char.lower())
        else:
            result.append(char.lower())
    return ''.join(result)


def convert_keys(obj):
    """递归转换对象中的所有键名为 snake_case"""
    if isinstance(obj, dict):
        return {camel_to_snake(k): convert_keys(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_keys(item) for item in obj]
    else:
        return obj


def convert_token(token_obj):
    """转换单个 token 对象"""
    # 先转换所有键名为 snake_case
    converted = convert_keys(token_obj)

    # 修改特定字段值
    converted['auth_method'] = 'social'
    converted['provider'] = 'imported'

    # 添加 type 字段
    converted['type'] = 'kiro'

    return converted


def main():
    # 读取源文件
    source_file = Path('/Users/you/Work/CLIProxyAPIPlus/tokens_export.json')
    output_dir = Path('/Users/you/Work/CLIProxyAPIPlus/auths')

    with open(source_file, 'r', encoding='utf-8') as f:
        tokens = json.load(f)

    print(f"共读取 {len(tokens)} 个 token 对象")

    # 转换每个对象并保存
    for i, token in enumerate(tokens, 1):
        # 转换对象
        converted = convert_token(token)

        # 生成文件名（使用 email 字段）
        email = converted.get('email', f'unknown_{i}')
        filename = f"kiro-{email}.json"
        output_path = output_dir / filename

        # 保存文件
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(converted, f, indent=2, ensure_ascii=False)

        email = converted.get('email', 'N/A')
        print(f"[{i}/{len(tokens)}] 已保存: {filename} (email: {email})")

    print(f"\n✅ 转换完成！共生成 {len(tokens)} 个文件")


if __name__ == '__main__':
    main()
