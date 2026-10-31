#!/usr/bin/env bash

set -euo pipefail

repo="btcsuite/btcwallet"
root="$(git rev-parse --show-toplevel)"
out_dir="${root}/docs/developer/sql_port_inventory"

interface_prs=(
    1050 1052 1059 {1068..1076} 1084 1085 1091 1092 1095 1100 1108
    1110 1118 {1126..1130} 1137 {1144..1146} 1148 1152 {1155..1157}
    {1159..1161} 1164
)
sql_prs=(
    1051 1065 1096 1099 1101 1111 1115 1121 1125 1131 1132
    {1134..1136} 1138 1139 {1141..1143} 1147 1154 1158 1162 1165
    1166 {1168..1174} 1181 1182 {1185..1190} 1192 1193 {1195..1202}
    1204 1206 {1208..1212} 1214 1216 1217 {1219..1225} {1227..1233}
    {1237..1248} {1252..1254} {1256..1258} {1260..1263} 1265
    {1267..1269} 1273 1277 1279
)
intermediate_prs=(1203 1215 1218 1236 1249 1255 1270 1271 1272)
umbrella_prs=(1083)

public_refactor=(
    1050 1052 1059 1076 1091 1092 1128 1129 1130 1211 1260
)
runtime_rewrite=(
    1137 1144 1145 1146 1148 1152 1155 1156 1157 1159 1160 1161
    1164 1258 1270 1271
)
key_vault_signing_rewrite=(
    1166 1170 1171 1224 1242 1249 1254 1265 1272 1273 1279
)
wallet_routing=(
    1188 1201 1202 1204 1214 1215 1228 1229 1230 1231 1236 1237
    1238 1239 1240 1243 1248 1253 1255
)
reusable_semantic_fix=(
    1168 1186 1187 1189 1193 1196 1197 1200 1208 1209 1210 1212
    1219 1220 1221 1222 1223 1225 1232 1241 1246 1247 1256 1257
    1262 1263 1267 1268 1269 1277
)
test_tooling=(
    {1068..1075} 1084 1085 1095 1099 1100 1108 1118 1121 1126
    1127 1136 1141 1154 1158 1169 1172 1173 1174 1190 1192
    1195 1198 1199 1206 1216 1217 1227 1233 1244 1245 1252
    1261
)
superseded_work=(1083 1110 1181 1203 1218)
sql_foundation=(
    1051 1065 1096 1101 1111 1115 1125 1131 1132 1134 1135 1138
    1139 1142 1143 1147 1162 1165 1182 1185
)

contains() {
    local needle="$1"
    shift

    local item
    for item in "$@"; do
        if [[ "${item}" == "${needle}" ]]; then
            return 0
        fi
    done

    return 1
}

cohort_for() {
    local number="$1"

    if contains "${number}" "${interface_prs[@]}"; then
        echo "interface-wallet-target"
    elif contains "${number}" "${sql_prs[@]}"; then
        echo "sql-wallet-target"
    elif contains "${number}" "${intermediate_prs[@]}"; then
        echo "intermediate-feeder"
    elif contains "${number}" "${umbrella_prs[@]}"; then
        echo "master-umbrella"
    else
        return 1
    fi
}

category_for() {
    local number="$1"

    if contains "${number}" "${public_refactor[@]}"; then
        echo "public-refactor"
    elif contains "${number}" "${runtime_rewrite[@]}"; then
        echo "runtime-rewrite"
    elif contains "${number}" "${key_vault_signing_rewrite[@]}"; then
        echo "key-vault-signing-rewrite"
    elif contains "${number}" "${wallet_routing[@]}"; then
        echo "wallet-routing"
    elif contains "${number}" "${reusable_semantic_fix[@]}"; then
        echo "reusable-semantic-fix"
    elif contains "${number}" "${test_tooling[@]}"; then
        echo "test-tooling"
    elif contains "${number}" "${superseded_work[@]}"; then
        echo "superseded-work"
    elif contains "${number}" "${sql_foundation[@]}"; then
        echo "sql-foundation"
    else
        echo "PR ${number} has no disposition category" >&2
        return 1
    fi
}

action_for() {
    case "$1" in
    sql-foundation)
        echo "salvage-now"
        ;;
    reusable-semantic-fix)
        echo "salvage-after-parity-review"
        ;;
    wallet-routing)
        echo "rework-behind-current-api"
        ;;
    public-refactor | runtime-rewrite | key-vault-signing-rewrite)
        echo "defer-post-port"
        ;;
    test-tooling)
        echo "salvage-selectively"
        ;;
    superseded-work)
        echo "source-only"
        ;;
    *)
        return 1
        ;;
    esac
}

mkdir -p "${out_dir}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

expected_tsv="${tmp_dir}/expected.tsv"
for number in "${interface_prs[@]}" "${sql_prs[@]}" \
    "${intermediate_prs[@]}" "${umbrella_prs[@]}"; do

    cohort="$(cohort_for "${number}")"
    category="$(category_for "${number}")"
    action="$(action_for "${category}")"
    printf '%s\t%s\t%s\t%s\n' \
        "${number}" "${cohort}" "${category}" "${action}" \
        >> "${expected_tsv}"
done

if [[ "$(wc -l < "${expected_tsv}" | tr -d ' ')" != "152" ]]; then
    echo "expected 152 PRs" >&2
    exit 1
fi
if [[ "$(cut -f1 "${expected_tsv}" | sort -n | uniq | wc -l | tr -d ' ')" != "152" ]]; then
    echo "PR lists contain duplicates" >&2
    exit 1
fi

jq -Rn '[inputs | split("\t") | {
    number: .[0], cohort: .[1], category: .[2], action: .[3]
}]' < "${expected_tsv}" > "${tmp_dir}/expected.json"

gh api --paginate "repos/${repo}/pulls?state=all&per_page=100" \
    > "${tmp_dir}/pulls.json"

found_count="$(jq --slurpfile expected "${tmp_dir}/expected.json" '
    ($expected[0] | map(.number) | INDEX(.)) as $wanted |
    [.[] | select($wanted[.number | tostring])] | length
' "${tmp_dir}/pulls.json")"
if [[ "${found_count}" != "152" ]]; then
    echo "GitHub returned ${found_count} of 152 expected PRs" >&2
    exit 1
fi

inventory="${out_dir}/pr_inventory.csv"
printf '%s\n' \
    'number,cohort,state,base,head,head_repo,head_sha,author,title,url,disposition_category,port_first_action' \
    > "${inventory}"
jq -r --slurpfile expected "${tmp_dir}/expected.json" '
    INDEX(.number | tostring) as $pulls |
    $expected[0][] as $entry |
    $pulls[$entry.number] as $pr |
    [
        ($pr.number | tostring),
        $entry.cohort,
        (if $pr.merged_at then "MERGED" else ($pr.state | ascii_upcase) end),
        $pr.base.ref,
        $pr.head.ref,
        ($pr.head.repo.full_name // "deleted-fork"),
        $pr.head.sha,
        $pr.user.login,
        $pr.title,
        $pr.html_url,
        $entry.category,
        $entry.action
    ] | @csv
' "${tmp_dir}/pulls.json" >> "${inventory}"

refs="${out_dir}/source_refs.csv"
printf '%s\n' \
    'kind,name,fetch_repository,git_ref,head_repository,sha,pr_number,commit_url,reason' \
    > "${refs}"

for branch in master interface-wallet sql-wallet; do
    branch_json="$(gh api "repos/${repo}/branches/${branch}")"
    sha="$(jq -r '.commit.sha' <<< "${branch_json}")"
    pr_number=""
    reason="source branch"
    case "${branch}" in
    interface-wallet)
        pr_number="1083"
        reason="interface rewrite umbrella tip"
        ;;
    sql-wallet)
        pr_number="1110"
        reason="SQL rewrite umbrella tip"
        ;;
    master)
        reason="port-first baseline"
        ;;
    esac

    jq -rn --arg name "${branch}" --arg repo "${repo}" \
        --arg ref "refs/heads/${branch}" --arg sha "${sha}" \
        --arg pr "${pr_number}" --arg reason "${reason}" '
        ["branch", $name, $repo, $ref, $repo, $sha, $pr,
         ("https://github.com/" + $repo + "/commit/" + $sha), $reason] |
        @csv
    ' >> "${refs}"
done

jq -r --slurpfile expected "${tmp_dir}/expected.json" '
    ($expected[0] | map(.number) | INDEX(.)) as $wanted |
    [.[] |
     select($wanted[.number | tostring]) |
     select(.state == "open") |
     select(.number != 1083 and .number != 1110)] |
    sort_by(.number)[] |
    [
        "open-feeder-pr",
        ("pr-" + (.number | tostring)),
        "btcsuite/btcwallet",
        ("refs/pull/" + (.number | tostring) + "/head"),
        (.head.repo.full_name // "deleted-fork"),
        .head.sha,
        (.number | tostring),
        ("https://github.com/btcsuite/btcwallet/commit/" + .head.sha),
        "open feeder head"
    ] | @csv
' "${tmp_dir}/pulls.json" >> "${refs}"

echo "wrote ${inventory}"
echo "wrote ${refs}"
