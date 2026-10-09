# TGPN — Telegram Web Proxy on Cloudflare Workers

> **⚡ نصب یک‌کلیک:** [https://nodeoof.github.io/TGPN/](https://nodeoof.github.io/TGPN/) — فقط توکن Cloudflare و اطلاعات بات رو بده، بقیه خودکار انجام می‌شه.

---

نسخه: **8.0.0**
یک پروکسی وب تلگرام (MTProto) کامل، سبک و رایگان که روی **Cloudflare Workers** اجرا می‌شود. با رابط کاربری ربات تلگرام برای مدیریت آسان.

---

## 🚀 ویژگی‌ها

| ویژگی | توضیح |
|--------|-------|
| **رایگان و بدون سرور** | اجرا روی Cloudflare Workers (Free Tier) — نیاز به VPS ندارد |
| **پشتیبانی MTProto** | پروتکل رسمی تلگرام با رمزنگاری AES-CTR |
| **ورودی دوگانه** | هم `?bridge=` (Desktop) و هم `?server=&secret=` (موبایل/وب) |
| **WebSocket Transport** | انتقال داده با تداخل و کنترل جریان (Flow Control) |
| **Durable Objects** | مدیریت جلسه (Session) با حالت‌پذیری (Stateful) |
| **KV Storage** | ذخیره پیکربندی پروکسی‌ها و نشست‌ها |
| **ربات تلگرام** | مدیریت کامل: ساخت، لیست، فعال/غیرفعال، حذف |
| **امنیت بالا** | HMAC امضا، توکن‌های کوتاه‌مدت، CSP سخت‌گیرانه |
| **بدون لاگ траفیک** | داده‌های کاربران ذخیره نمی‌شوند |

---

## 🏗 معماری

```
┌─────────────────────────────────────────────────────────────┐
│                      Cloudflare Edge                        │
├─────────────────────────────────────────────────────────────┤
│  Worker (worker.js)                                         │
│  ├── /healthz                    → Health Check             │
│  ├── /bot/webhook                → Telegram Bot Webhook     │
│  ├── /api/v1/session (POST)      → Create Session + Hello  │
│  ├── /api/v1/session (DELETE)    → Close Session           │
│  ├── /api/v1/ws                  → WebSocket Upgrade       │
│  ├── /?bridge=<capability>       → Desktop Entry (tdesktop)│
│  ├── /?server=X&secret=Y         → Mobile/Web Deep Link    │
│  └── /                            → Public Landing Page    │
├─────────────────────────────────────────────────────────────┤
│  Durable Object: ProxySession                               │
│  ├── WebSocket ↔ Client (Browser)                           │
│  ├── TCP Socket ↔ Telegram DC (MTProto)                     │
│  ├── Stream Multiplexing (Frame Protocol)                   │
│  ├── Flow Control (Window-based)                            │
│  └── AES-CTR Encryption (Client↔Proxy, Proxy↔Telegram)     │
├─────────────────────────────────────────────────────────────┤
│  KV: PROXY_REGISTRY                                         │
│  ├── proxy:{id}          → {id, name, secret, owner, ...}  │
│  ├── secret:{hex}        → proxyId (reverse lookup)        │
│  ├── session:{token}     → {proxyId, exp} (TTL 15 min)     │
│  ├── user:{uid}:proxies  → [proxyId, ...]                   │
│  └── all:proxies         → [proxyId, ...] (for bridge)     │
└─────────────────────────────────────────────────────────────┘
```

---

## 📋 پیش‌نیازها

- اکانت **Cloudflare** (رایگان)
- **Node.js** ≥ 18 و **npm**/`wrangler`
- یک **ربات تلگرام** (از @BotFather بگیرید)
- (اختیاری) دامنه شخصی برای `PUBLIC_HOSTNAME`

---

## ⚡ نصب سریع

### 1. کلون و وابستگی‌ها

```bash
git clone <your-repo-url> TGPN
cd TGPN
npm install -g wrangler
wrangler login
```

### 2. ایجاد Namespaceهای KV و Durable Object

```bash
# KV Namespace برای ذخیره پروکسی‌ها و نشست‌ها
wrangler kv:namespace create PROXY_REGISTRY
# کپی ID خروجی را در wrangler.toml قرار دهید

# Migration برای Durable Object (SQLite class)
# در wrangler.toml موجود است: new_sqlite_classes = ["ProxySession"]
```

### 3. پیکربندی `wrangler.toml`

```toml
name = "tgpn"
main = "worker.js"
compatibility_date = "2025-01-01"
compatibility_flags = ["nodejs_compat"]

[vars]
PUBLIC_HOSTNAME = "your-subdomain.workers.dev"  # یا دامنه شخصی
TELEGRAM_BOT_USERNAME = "your_bot_username"
ADMIN_IDS = "123456789,987654321"               # آیدی‌های ادمین (کاما جدا)

[[kv_namespaces]]
binding = "PROXY_REGISTRY"
id = "YOUR_KV_NAMESPACE_ID_HERE"

[[durable_objects.bindings]]
name = "PROXY_SESSIONS"
class_name = "ProxySession"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["ProxySession"]
```

### 4. تنظیم Secrets (مهم)

```bash
# توکن ربات تلگرام (از BotFather)
wrangler secret put TELEGRAM_BOT_TOKEN

# Secret وب‌هوک (رشته تصادفی قوی، برای اعتبارسنجی درخواست‌های تلگرام)
wrangler secret put TELEGRAM_WEBHOOK_SECRET
```

### 5. Deploy

```bash
wrangler deploy
```

### 6. ست کردن Webhook ربات

```bash
# جایگزین YOUR_WORKER_URL با آدرس worker شما
curl -X POST "https://api.telegram.org/bot<TELEGRAM_BOT_TOKEN>/setWebhook" \
  -d "url=https://YOUR_WORKER_URL/bot/webhook" \
  -d "secret_token=<TELEGRAM_WEBHOOK_SECRET>" \
  -d "allowed_updates=[\"message\",\"edited_message\",\"callback_query\"]"
```

---

## 🎮 استفاده از ربات

| دستور | توضیح |
|--------|-------|
| `/start` یا `/menu` | منوی اصلی |
| `/new [نام]` | ساخت پروکسی جدید (اختیاری: نام) |
| `/list` | لیست پروکسی‌های شما |
| `/myid` | نمایش آیدی تلگرام شما |
| `/version` | نسخه Worker |
| `/cancel` | لغو عملیات در حال انجام |

**دکمه‌های اینلاین:**
- ➕ **ساخت پروکسی جدید** → ورود نام → دریافت لینک اتصال
- 📋 **پروکسی‌های من** → مشاهده لیست + مدیریت
- ℹ️ **جزئیات پروکسی** → Secret، لینک `t.me/webproxy`، کپی، Toggle، حذف

---

## 🔗 اتصال کلاینت‌ها

### Desktop (Telegram Desktop / tdlib)
```
https://your-domain.workers.dev/?bridge=<43-char-capability>
```
*این لینک در ربات با دکمه «باز کردن در تلگرام» تولید می‌شود.*

### Mobile / Web (t.me/webproxy deep link)
```
https://t.me/webproxy?server=your-domain.workers.dev&secret=<32-hex-secret>
```
*Secret همان مقدار ۳۲ کاراکتر هگزادسیمال است که در ربات نمایش داده می‌شود.*

---

## 🔐 امنیت و بهترین شیوه‌ها

1. **TELEGRAM_WEBHOOK_SECRET** باید یک رشته تصادفی طولانی باشد (مثلاً `openssl rand -hex 32`)
2. **ADMIN_IDS** فقط آیدی‌های عددی کاربران مورد اعتماد
3. **PUBLIC_HOSTNAME** دقیقاً همان هاستی باشد که Worker روی آن در دسترس است (برای جلوگیری از Host Header Injection)
4. Secret پروکسی‌ها **۳۲ کاراکتر هگز** هستند — هرگز در لاگ‌ها یا چت‌های عمومی ندهید
5. توکن نشست (Session Token) عمر **۱۵ دقیقه** دارد و یک‌بار مصرف است

---

## 📦 ساختار پروژه

```
TGPN/
├── worker.js          # کد کامل Worker (Entry Point + All Logic)
├── wrangler.toml      # پیکربندی Cloudflare
├── .gitignore         # فایل‌های نادیده‌گرفته شده
├── .wrangler/         # Cache محلی Wrangler (gitignore)
├── index.html         # نصب‌کننده وب (Web Installer)
├── FILE/              # ماژول‌های داخلی (protocol, session, bridge, ...)
│   ├── protocol.js
│   ├── session.js
│   ├── bridge.js
│   ├── mtproxy.js
│   └── index.js
└── tgpn-proxy/        # CORS Proxy جداگانه برای Cloudflare API
    ├── cors-proxy.js
    └── wrangler.toml
```
---

## 🛠 متغیرهای محیطی (wrangler.toml `[vars]`)

| متغیر | پیش‌فرض | توضیح |
|--------|---------|-------|
| `PUBLIC_HOSTNAME` | (worker subdomain) | هاست عمومی برای چک Origin و لینک‌های اتصال |
| `TELEGRAM_BOT_USERNAME` | — | یوزرنیم ربات (بدون @) برای دکمه‌های deep link |
| `ADMIN_IDS` | — | لیست آیدی‌های ادمین (کاما جدا) |
| `MAX_STREAMS` | `64` | حداکثر استریم همزمان هر نشست (1–128) |
| `SESSION_TTL_SECONDS` | `300` | عمر Bootstrap Token (۳۰–۶۰۰ ثانیه) |

---

## 📊 مانیتورینگ و لاگ‌ها

```bash
# لاگ‌های زنده
wrangler tail

# فقط خطاها
wrangler tail --status=error

# جستجو در لاگ‌ها
wrangler tail --search="proxy"
```

**Health Check:**
```
GET https://your-domain.workers.dev/healthz
# Response: {"ok":true,"version":"8.0.0","carrier":"websocket"}
```

---

## 🧪 تست محلی

```bash
# با Miniflare (شبیه‌سازی کامل Workers + KV + DO)
npx wrangler dev --local

# تست health
curl http://localhost:8787/healthz
```

---

## 📝 نکات فنی مهم

### Frame Protocol (باینری)
```
Header (8 bytes): [TYPE:1][STREAM_ID:3][LENGTH:4]
Payload: LENGTH bytes
Types: 0x01=OPEN, 0x02=DATA, 0x03=CLOSE, 0x04=WINDOW, 0x05=PING, 0x06=PONG, 0x10=HELLO, 0x11=WELCOME, 0x1F=BYE
```

### Flow Control
- **Initial Window**: 4MB در هر طرف
- **Window Update** با فریم `WINDOW` (4-byte amount)
- **Backpressure** در سطح Session و Stream

### MTProto Handshake
1. Client → 64-byte packet (encrypted with secret-derived keys)
2. Proxy →--tag/DC, derive keys
3. Proxy → Telegram DC (443) با Handshake جدید
4. دو طرف AES-CTR streams برقرار می‌کنند

---

## 🐛 عیب‌یابی رایج

| مشکل | راه‌حل |
|-------|--------|
| `proxy not found` | Secret اشتباه یا پروکسی حذف شده |
| `invalid proxy id` | Header `X-Proxy-Id` نامعتبر |
| `session closed` / `unknown session` | توکن منقضی شده (۱۵ دقیقه) |
| `websocket_close` | کلاینت قطع کرده یا timeout |
| `connect timeout` | دسترسی به Telegram DC مسدود (چک Cloudflare IP) |
| Bot جواب نمی‌دهد | Webhook ست نشده، Secret اشتباه، یا Worker down |

---

## 📄 لایسنس

MIT License — استفاده آزاد، تغییر و توزیع با حفظ کپی‌رایت.

---

## 🙏 تشکر

- **Cloudflare Workers** برای پلتفرم رایگان و قدرتمند
- **Telegram** برای پروتکل MTProto و WebProxy Bot API
- جامعه اوپن‌سورس برای الهام و ابزارها
- **[ArasTey/TWP-CF](https://github.com/ArasTey/TWP-CF)** — الهام‌گرفته از ایده و معماری این پروژه

---

> **نکته:** این پروژه برای استفاده شخصی/تیمی طراحی شده. برای ترافیک بالا یا استفاده تجاری، محدودیت‌های Cloudflare Free Tier را در نظر بگیرید.
