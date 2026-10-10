#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2026 honeok <i@honeok.com>

set -eEuo pipefail

curl() {
    local i rc

    for ((i = 1; i <= 3; i++)); do
        if command curl --connect-timeout 10 --fail --show-error --insecure "$@"; then
            return 0
        else
            rc="$?"
            if ((rc == 22 || i == 3)); then
                return "$rc"
            fi
            sleep 1
        fi
    done
}

## 获取 Spamhaus 恶意 ASN
DROP_ASNS="$(curl -Ls https://www.spamhaus.org/drop/asndrop.json | jq -sr 'if .[-1].type == "metadata" and .[-1].records == (length - 1)
    then .[:-1][] | "AS\(.asn)" else error("invalid feed") end' | sort -u)"

## 获取 Cloudflare 现有规则
for ((i = 1; ; i++)); do
    response="$(curl -s -H "Authorization: Bearer $CF_API_TOKEN" \
        "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/firewall/access_rules/rules?page=$i&per_page=100")"
    # 汇总所有规则, 每行一个 JSON 对象
    CURRENT_RULES+="$(jq -c 'if .success then .result[] else error("API failed") end' <<< "$response")"$'\n'
    # 当前页码达到总页数时, 退出分页循环
    ((i >= $(jq -er '.result_info.total_pages' <<< "$response"))) && break
done

# 提取 Cloudflare 已封禁的 ASN 及规则 ID, 用于同步和删除
CURRENT_ASNS="$(jq -r 'select(.mode == "block" and .configuration.target == "asn") | [.configuration.value, .id] | @tsv' <<< "$CURRENT_RULES")"

# 提取 Spamhaus 新增的 ASN
TO_ADD="$(comm -23 <(sort -u <<< "$DROP_ASNS") <(cut -f1 <<< "$CURRENT_ASNS" | sort -u))"

# 提取 Spamhaus 已下榜的 ASN 及 Cloudflare 规则 ID
TO_DELETE="$(while IFS=$'\t' read -r asn rule_id; do
    [ -n "$asn" ] || continue
    grep -Fxq "$asn" <<< "$DROP_ASNS" || printf '%s\t%s\n' "$asn" "$rule_id"
done <<< "$CURRENT_ASNS")"

# 新增 Spamhaus 恶意 ASN
while IFS= read -r asn; do
    [ -n "$asn" ] || continue
    payload="$(jq -nc --arg asn "$asn" '{mode:"block",configuration:{target:"asn",value:$asn},notes:"asn-drop"}')"
    response="$(curl -s -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" -d "$payload" \
        "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/firewall/access_rules/rules")"
    jq -e '.success == true' <<< "$response" > /dev/null
    echo "Added: $asn"
done <<< "$TO_ADD"

# 删除 Spamhaus 已下榜的 ASN
while IFS=$'\t' read -r asn rule_id; do
    [ -n "$rule_id" ] || continue
    response="$(curl -s -X DELETE -H "Authorization: Bearer $CF_API_TOKEN" \
        "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/firewall/access_rules/rules/$rule_id")"
    jq -e '.success == true' <<< "$response" > /dev/null
    echo "Deleted: $asn"
done <<< "$TO_DELETE"
