#!/usr/bin/env bash
# mihomo-pull.sh：主机侧拉取。从发布器拉本机配置 → mihomo -t 校验 → 原子替换 → PUT /configs 热重载 → 恢复分组选择。
# 失败时保留旧配置（重载失败会回滚到旧文件并再次重载）。未变化（304）时什么都不做。
#
# 用法：mihomo-pull.sh [ENV_FILE]      默认 ENV_FILE=${MIHOMO_PULL_ENV:-$HOME/.config/mihomo-pull.env}
# ENV_FILE（chmod 600）示例：
#   PULL_URL=http://100.x.y.z:7898/myhost.yaml
#   PULL_TOKEN=<本机 publish token>
#   MIHOMO_BIN=/usr/local/bin/mihomo
#   MIHOMO_DIR=/etc/mihomo                 # mihomo -d 目录（geo 数据、cache.db）
#   MIHOMO_CONFIG=/etc/mihomo/config.yaml  # 必须位于 MIHOMO_DIR 内（mihomo 的 SAFE_PATHS 限制）
#   STATE_DIR=/var/lib/mihomo-pull         # 可选，存 ETag 与备份；默认 $MIHOMO_DIR/.pull
#   CONTROLLER=127.0.0.1:9090              # 可选；默认读配置里的 external-controller
# 依赖：bash、curl、python3（解析控制器 JSON）。
set -uo pipefail
ENV_FILE=${1:-${MIHOMO_PULL_ENV:-$HOME/.config/mihomo-pull.env}}
[ -f "$ENV_FILE" ] || { echo "mihomo-pull: 缺少 $ENV_FILE" >&2; exit 2; }
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a
: "${PULL_URL:?PULL_URL 未设置}" "${PULL_TOKEN:?PULL_TOKEN 未设置}" "${MIHOMO_DIR:?MIHOMO_DIR 未设置}"
MIHOMO_BIN=${MIHOMO_BIN:-mihomo}
MIHOMO_CONFIG=${MIHOMO_CONFIG:-$MIHOMO_DIR/config.yaml}
STATE_DIR=${STATE_DIR:-$MIHOMO_DIR/.pull}
mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"
umask 077
log() { echo "mihomo-pull: $*"; }

# 控制器访问：地址与 secret 从指定配置文件读取（不打印 secret）
yget() { sed -n "s/^$1:[[:space:]]*//p" "$2" 2>/dev/null | head -1 | sed -e "s/^['\"]//" -e "s/['\"][[:space:]]*\$//" -e 's/[[:space:]]*$//'; }
ctrl_of() { local c=${CONTROLLER:-$(yget external-controller "$1")}; c=${c:-127.0.0.1:9090}; c=${c/#0.0.0.0/127.0.0.1}; c=${c/#:/127.0.0.1:}; echo "$c"; }
api() { # api CONFIG_FOR_SECRET METHOD PATH [DATA]
  local cfg=$1 m=$2 p=$3 d=${4:-} s; s=$(yget secret "$cfg")
  curl -fsS -m 10 --noproxy '*' -X "$m" ${s:+-H "Authorization: Bearer $s"} -H 'Content-Type: application/json' \
    ${d:+--data "$d"} "http://$(ctrl_of "$cfg")$p"
}
save_selections() { # 当前所有 Selector 的选择 → JSON
  api "$1" GET /proxies 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)["proxies"]
print(json.dumps({k:v["now"] for k,v in d.items() if v.get("type")=="Selector" and v.get("now")}, ensure_ascii=False))' 2>/dev/null
}
restore_selections() { # 先恢复旧选择；旧选择不存在时用配置头部的 cocp-selections 默认值
  local cfg=$1 prev=${2:-"{}"} defaults
  defaults=$(sed -n 's/^# cocp-selections: //p' "$cfg" | head -1); defaults=${defaults:-"{}"}
  api "$cfg" GET /proxies 2>/dev/null | PREV=$prev DEF=$defaults python3 -c '
import json,os,sys
cur=json.load(sys.stdin)["proxies"]; prev=json.loads(os.environ["PREV"]); dflt=json.loads(os.environ["DEF"])
for g,v in cur.items():
  if v.get("type")!="Selector": continue
  opts=v.get("all",[]); want=None
  if g in prev and prev[g] in opts: want=prev[g]
  else:
    d=dflt.get(g); d=d if isinstance(d,list) else ([d] if d else [])
    want=next((o for x in d for o in opts if o==x),None) or next((o for x in d for o in opts if o.startswith(x)),None)
  if want and want!=v.get("now"): print(g+"\t"+want)' 2>/dev/null | while IFS=$'\t' read -r g n; do
    enc=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$g")
    body=$(python3 -c 'import json,sys;print(json.dumps({"name":sys.argv[1]},ensure_ascii=False))' "$n")
    api "$cfg" PUT "/proxies/$enc" "$body" >/dev/null 2>&1 && echo "  选择 $g → $n"
  done
}
rule_count() { awk '/^rules:/{r=1;next} r&&/^[^ #-]/{r=0} r&&/^ *- /{n++} END{print n+0}' "$1"; }
reload() { api "$1" PUT '/configs?force=true' "$(python3 -c 'import json,sys;print(json.dumps({"path":sys.argv[1]}))' "$2")" >/dev/null; }

# 1) 拉取（带 ETag）
ETAG_FILE=$STATE_DIR/etag; NEW=$STATE_DIR/config.new.yaml; HDR=$STATE_DIR/headers
etag=; [ -s "$MIHOMO_CONFIG" ] && [ -s "$ETAG_FILE" ] && etag=$(cat "$ETAG_FILE")
code=$(curl -sS -m 60 --noproxy '*' -o "$NEW" -D "$HDR" -w '%{http_code}' \
  -H "Authorization: Bearer $PULL_TOKEN" ${etag:+-H "If-None-Match: $etag"} "$PULL_URL") || { log "拉取失败（网络），保留现有配置"; rm -f "$NEW"; exit 1; }
case $code in
  304) rm -f "$NEW"; log "未变化 (304) etag=$etag"; exit 0;;
  200) ;;
  *) rm -f "$NEW"; log "拉取失败 HTTP $code，保留现有配置"; exit 1;;
esac
new_etag=$(sed -n 's/^[Ee][Tt][Aa][Gg]:[[:space:]]*//p' "$HDR" | tr -d '\r' | tail -1)
grep -qE '^(proxies|proxy-groups|rules):' "$NEW" || { rm -f "$NEW"; log "下载内容不像 mihomo 配置，保留现有配置"; exit 1; }

# 2) 校验
if ! out=$("$MIHOMO_BIN" -t -d "$MIHOMO_DIR" -f "$NEW" 2>&1); then
  rm -f "$NEW"; log "mihomo -t 校验失败，保留现有配置：$(echo "$out" | grep -iE 'error|fatal' | tail -2 | sed -E 's#://[^ ]+#://***#g')"; exit 1
fi

# 3) 原子替换（保留一份旧配置用于回滚）
running=; [ -s "$MIHOMO_CONFIG" ] && api "$MIHOMO_CONFIG" GET /version >/dev/null 2>&1 && running=1
prev_sel="{}"; [ -n "$running" ] && prev_sel=$(save_selections "$MIHOMO_CONFIG"); prev_sel=${prev_sel:-"{}"}
[ -s "$MIHOMO_CONFIG" ] && cp -p "$MIHOMO_CONFIG" "$STATE_DIR/config.prev.yaml"
OLD_FOR_API=$STATE_DIR/config.prev.yaml
chmod 600 "$NEW" && mv -f "$NEW" "$MIHOMO_CONFIG"

# 4) 热重载（用旧配置里的 secret 访问控制器；重载后换新 secret）
if [ -n "$running" ]; then
  if reload "$OLD_FOR_API" "$MIHOMO_CONFIG"; then
    sleep 1
    if api "$MIHOMO_CONFIG" GET /version >/dev/null 2>&1; then
      restore_selections "$MIHOMO_CONFIG" "$prev_sel"
      echo "$new_etag" > "$ETAG_FILE"
      log "已更新并热重载 etag=$new_etag rules=$(rule_count "$MIHOMO_CONFIG")"
      exit 0
    fi
    log "重载后控制器不可达，回滚"
  else
    log "热重载失败，回滚"
  fi
  cp -p "$MIHOMO_CONFIG" "$STATE_DIR/config.failed.yaml"
  cp -p "$OLD_FOR_API" "$MIHOMO_CONFIG"
  reload "$OLD_FOR_API" "$MIHOMO_CONFIG" >/dev/null 2>&1 || reload "$STATE_DIR/config.failed.yaml" "$MIHOMO_CONFIG" >/dev/null 2>&1
  restore_selections "$MIHOMO_CONFIG" "$prev_sel" >/dev/null
  exit 1
fi
echo "$new_etag" > "$ETAG_FILE"
log "已写入新配置 etag=$new_etag（内核未运行，下次启动生效）"
