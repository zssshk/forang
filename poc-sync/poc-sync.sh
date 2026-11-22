#!/bin/bash
# poc-collection -> FORANG PoC 库 同步（幂等）。
# 流程: git pull -> 重签 JWT（容器重建 jwt.key 会变）-> 增量导入。
# 由 systemd timer 或 cron 调用；也可手动跑。
set -euo pipefail

REPO=/root/poc-collection
SRC=/root/forang-src/poc-sync
KEY_SSH="ssh -i /root/.ssh/id_ed25519_github -o IdentitiesOnly=yes -o BatchMode=yes"
BASE=http://127.0.0.1:8787
TOKEN=/tmp/forang.token

log() { echo "[poc-sync $(date '+%F %T')] $*"; }

# 1) 拉最新
if [ ! -d "$REPO/.git" ]; then
  log "首次克隆"
  GIT_SSH_COMMAND="$KEY_SSH" git clone -q git@github.com:zssshk/poc-collection.git "$REPO"
else
  cd "$REPO"
  GIT_SSH_COMMAND="$KEY_SSH" git pull -q --ff-only origin main \
    || { log "pull 失败（可能本地有改动），放弃本次同步"; exit 1; }
fi
HEAD=$(git -C "$REPO" rev-parse --short HEAD)
log "repo HEAD=$HEAD"

# 2) 重签 JWT（面板密码无关；jwt.key 容器重建后变化）
docker cp forang-deploy-artex-1:/app/jwt.key /tmp/jwt.key >/dev/null
python3 - "$TOKEN" <<'PYEOF'
import hmac, hashlib, base64, json, time, sys
k = open('/tmp/jwt.key', 'rb').read()
b64 = lambda d: base64.urlsafe_b64encode(d).rstrip(b'=')
h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(',', ':')).encode())
p = b64(json.dumps({"sub": "FORANG", "exp": int(time.time()) + 7 * 86400},
                   separators=(',', ':')).encode())
s = b64(hmac.new(k, h + b'.' + p, hashlib.sha256).digest())
open(sys.argv[1], 'w').write((h + b'.' + p + b'.' + s).decode())
PYEOF

# 2b) gate cookie（gate 开启时 gateMiddleware 在最外层，无 cookie 一律裸 404，
#     与"路由不存在"无法从响应区分——这正是本脚本长期失败在 404 的原因）。
#     cookie = hex(HMAC-SHA256(jwtKey, "artex-gate-v1|" + gateToken))，见 server/gate.go。
GATE=/tmp/forang.gate
GT=$(docker exec forang-deploy-postgres-1 psql -U "${POSTGRES_USER:-artex}" \
       -d "${POSTGRES_DB:-artex}" -tA \
       -c "select value from settings where key='gate.token';" 2>/dev/null | tr -d '[:space:]')
if [ -n "${GT:-}" ]; then
  python3 - "$GT" > "$GATE" <<'PYGATE'
import hmac, hashlib, sys
mac = hmac.new(open('/tmp/jwt.key', 'rb').read(),
              b'artex-gate-v1|' + sys.argv[1].encode(), hashlib.sha256)
print(mac.hexdigest(), end='')
PYGATE
  log "gate 已启用，cookie 已复算（${#GT} 位 token）"
else
  : > "$GATE"
  log "gate 未启用，跳过 cookie"
fi

# 3) 增量导入
log "开始导入"
python3 "$SRC/import_pocs.py" "$REPO" "$BASE" "$TOKEN"
log "完成"
