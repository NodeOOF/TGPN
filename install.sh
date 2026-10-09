#!/usr/bin/env bash
# TGProxyNode Installer v8.0.0

set -e
C="\033[36m"; G="\033[32m"; R="\033[31m"; Y="\033[33m"; B="\033[1m"; N="\033[0m"

echo ""
echo -e "${C}${B}🌐 TGProxyNode Installer v8.0.0${N}"
echo -e "${C}────────────────────────────${N}"
echo ""

# ── چک پیش‌نیازها ──
for cmd in node npm curl; do
  command -v $cmd >/dev/null || { echo -e "${R}✗ $cmd نصب نیست${N}"; exit 1; }
done

command -v wrangler >/dev/null || npm install -g wrangler >/dev/null 2>&1
echo -e "${G}✓${N} پیش‌نیازها آماده"

# ── گرفتن اطلاعات از کاربر ──
echo ""
echo -e "${Y}🔑 توکن Cloudflare رو از این لینک بساز:${N}"
echo ""
echo "   https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22workers_subdomain%22%2C%22type%22%3A%22edit%22%7D%5D&accountId=*&zoneId=all&name=TGProxyNode-Setup"
echo ""
read -s -p "   توکن: " CF_TOKEN
echo ""
[ -z "$CF_TOKEN" ] && { echo -e "${R}✗ توکن خالیه${N}"; exit 1; }

echo ""
read -p "   نام Worker [tgproxynode]: " WORKER_NAME
WORKER_NAME=${WORKER_NAME:-tgproxynode}

read -p "   یوزرنیم بات تلگرام (بدون @): " BOT_USERNAME
[ -z "$BOT_USERNAME" ] && { echo -e "${R}✗ اجباریه${N}"; exit 1; }

read -p "   آیدی عددی تلگرام (از @userinfobot): " ADMIN_ID
[ -z "$ADMIN_ID" ] && { echo -e "${R}✗ اجباریه${N}"; exit 1; }

read -s -p "   توکن بات (از @BotFather): " BOT_TOKEN
echo ""
[ -z "$BOT_TOKEN" ] && { echo -e "${R}✗ اجباریه${N}"; exit 1; }

# ── تأیید توکن ──
echo ""
echo -e "${C}⏳ در حال ساخت...${N}"
echo ""

ACCOUNT_ID=$(curl -s "https://api.cloudflare.com/client/v4/accounts" \
  -H "Authorization: Bearer $CF_TOKEN" \
  | grep -oE '"id":"[a-f0-9]{32}"' | head -1 | cut -d'"' -f4)

[ -z "$ACCOUNT_ID" ] && { echo -e "${R}✗ توکن نامعتبره${N}"; exit 1; }
echo -e "${G}✓${N} اکانت: $ACCOUNT_ID"

# ── ساخت KV ──
KV_RESP=$(curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/storage/kv/namespaces" \
  -H "Authorization: Bearer $CF_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"title\":\"${WORKER_NAME}-kv\"}")

KV_ID=$(echo "$KV_RESP" | grep -oE '"id":"[a-f0-9]{32}"' | head -1 | cut -d'"' -f4)
[ -z "$KV_ID" ] && { echo -e "${R}✗ ساخت KV ناموفق:${N}"; echo "$KV_RESP"; exit 1; }
echo -e "${G}✓${N} KV: $KV_ID"

# ── Subdomain ──
SUB=$(curl -s "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/subdomain" \
  -H "Authorization: Bearer $CF_TOKEN" \
  | grep -oE '"subdomain":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$SUB" ]; then
  RANDOM_SUB="tgpn-$(node -e "console.log(require('crypto').randomBytes(3).toString('hex'))")"
  curl -s -X PUT "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/subdomain" \
    -H "Authorization: Bearer $CF_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"subdomain\":\"$RANDOM_SUB\"}" >/dev/null
  sleep 3
  SUB=$(curl -s "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/subdomain" \
    -H "Authorization: Bearer $CF_TOKEN" \
    | grep -oE '"subdomain":"[^"]*"' | head -1 | cut -d'"' -f4)
  [ -z "$SUB" ] && SUB="$RANDOM_SUB"
fi

PUBLIC_HOST="${WORKER_NAME}.${SUB}.workers.dev"
echo -e "${G}✓${N} آدرس: https://$PUBLIC_HOST"

# ── دانلود worker.js ──
WORK_DIR=$(mktemp -d)
cd "$WORK_DIR"
curl -fsSL "https://raw.githubusercontent.com/NodeOOF/TGPN/main/worker.js" -o worker.js
echo -e "${G}✓${N} worker.js دانلود شد"

# ── ساخت wrangler.toml ──
cat > wrangler.toml <<EOF
name = "$WORKER_NAME"
main = "worker.js"
compatibility_date = "2025-10-01"
compatibility_flags = ["nodejs_compat"]

[vars]
PUBLIC_HOSTNAME = "$PUBLIC_HOST"
TELEGRAM_BOT_USERNAME = "$BOT_USERNAME"
ADMIN_IDS = "$ADMIN_ID"

[[kv_namespaces]]
binding = "PROXY_REGISTRY"
id = "$KV_ID"

[[durable_objects.bindings]]
name = "PROXY_SESSIONS"
class_name = "ProxySession"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["ProxySession"]
EOF
echo -e "${G}✓${N} wrangler.toml ساخته شد"

# ── Secrets ──
export CLOUDFLARE_API_TOKEN="$CF_TOKEN"
export CLOUDFLARE_ACCOUNT_ID="$ACCOUNT_ID"

WEBHOOK_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")

echo "$BOT_TOKEN" | npx wrangler secret put TELEGRAM_BOT_TOKEN --name "$WORKER_NAME" >/dev/null 2>&1
echo -e "${G}✓${N} BOT_TOKEN ست شد"

echo "$WEBHOOK_SECRET" | npx wrangler secret put TELEGRAM_WEBHOOK_SECRET --name "$WORKER_NAME" >/dev/null 2>&1
echo -e "${G}✓${N} WEBHOOK_SECRET ست شد"

# ── Deploy ──
npx wrangler deploy >/dev/null 2>&1
echo -e "${G}✓${N} Worker deploy شد"

# ── Webhook ──
WEBHOOK_URL="https://api.telegram.org/bot${BOT_TOKEN}/setWebhook?url=https://${PUBLIC_HOST}/bot/webhook&secret_token=${WEBHOOK_SECRET}&allowed_updates=%5B%22message%22%2C%22edited_message%22%2C%22callback_query%22%5D"
curl -s "$WEBHOOK_URL" >/dev/null
echo -e "${G}✓${N} Webhook ثبت شد"

# ── پاکسازی ──
cd - >/dev/null
rm -rf "$WORK_DIR"

# ── تمام ──
echo ""
echo -e "${G}${B}═══════════════════════════════════════${N}"
echo -e "${G}${B}   ✅ TGProxyNode با موفقیت نصب شد!${N}"
echo -e "${G}${B}═══════════════════════════════════════${N}"
echo ""
echo -e "   🌐 آدرس:  ${C}https://$PUBLIC_HOST${N}"
echo -e "   🤖 بات:   ${C}@$BOT_USERNAME${N}"
echo ""
echo -e "   ${B}مرحله بعد:${N}"
echo -e "   1. برو در تلگرام به @$BOT_USERNAME"
echo -e "   2. /start رو بزن"
echo -e "   3. /new test رو بزن"
echo -e "   4. لینک رو باز کن"
echo ""
