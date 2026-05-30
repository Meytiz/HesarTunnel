# 🛡️ HESAR - High-Efficiency Secure Anti-Restriction Tunnel

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux-yellow)

**تانل ریورس با رمزنگاری مقاوم در برابر DPI ایران، چین و روسیه**

*Reverse Tunnel with DPI-Resistant Encryption for Iran, China & Russia*

</div>

---

## ✨ ویژگی‌ها | Features

- 🔒 **رمزنگاری قوی**: ChaCha20-Poly1305 / AES-256-GCM بدون نیاز به دامنه یا سرتیفیکیت
- 🎭 **SNI Spoofing**: جعل SNI برای دور زدن فیلترینگ DPI
- 🌐 **IP Spoofing**: جعل IP برای مقاومت در برابر DPI پیشرفته
- 🚀 **KCP**: پروتکل کم-تأخیر روی UDP با Reed-Solomon FEC
- 📊 **پنل GUI**: رابط کاربری فارسی/انگلیسی با چارت‌های Real-time
- ⚡ **بهینه‌سازی سرور**: BBR, sysctl tuning خودکار
- 🔄 **ریورس تانل**: سرور ایران نیازی به پورت باز ندارد

---

## 🚀 نصب سریع | Quick Start

### روش ۱ - نصب خودکار (توصیه‌شده)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Meytiz/hesar/main/scripts/install.sh)
```

### روش ۲ - نصب دستی (بدون دسترسی به GitHub از ایران)

اگر سرور ایران به GitHub دسترسی ندارد:

**گام ۱**: باینری را از طریق یک سیستم با اینترنت آزاد دانلود کنید:

```bash
# از سیستم دیگر (یا سرور خارج)
wget https://github.com/Meytiz/hesar/releases/latest/download/hesar-linux-amd64

# انتقال به سرور ایران
scp hesar-linux-amd64 root@IRAN_IP:/usr/local/bin/hesar
chmod +x /usr/local/bin/hesar
```

**گام ۲**: اسکریپت نصب را اجرا کنید:

```bash
bash /path/to/scripts/install.sh
```

---

## 📋 پیش‌نیازها | Requirements

| Component | Minimum |
|-----------|---------|
| OS        | Debian 10+ / Ubuntu 20.04+ / CentOS 8+ |
| RAM       | 256 MB |
| CPU       | 1 Core |
| Disk      | 50 MB |
| Go        | 1.22+ (فقط برای ساخت از سورس) |

---

## 🏗️ معماری | Architecture

```
کاربر (User)
    │
    ▼ TCP Connection
┌──────────────────┐        Reverse Tunnel (Encrypted)      ┌──────────────────┐
│  سرور ایران      │ ◄────────────────────────────────────── │  سرور خارج      │
│  (Iran Server)   │                                         │ (Foreign Server) │
│                  │    ChaCha20-Poly1305 / KCP / SNI        │                  │
│  Config Ports:   │    Port: CONN_PORT (Random)             │  Listens on      │
│  80, 443, ...    │                                         │  Config Ports    │
└──────────────────┘                                         └──────────────────┘
                                                                      │
                                                                      ▼
                                                              Target Service
                                                              (V2Ray/X-ray/etc)
```

**نکته مهم**: سرور خارج به سرور ایران متصل می‌شود (ریورس). بنابراین سرور ایران نیازی به پورت باز برای اتصال ندارد.

---

## 🔌 پروتکل‌ها | Protocols

### 1. KCP (توصیه‌شده برای سرعت)
```
مزایا: تأخیر کم، مقاومت در برابر packet loss، UDP (سخت‌تر برای فیلتر)
معایب: مصرف bandwidth بیشتر (FEC)
بهترین برای: گیمینگ، استریم، شرایط شبکه ضعیف
```

### 2. SNI Spoofing (توصیه‌شده برای دور زدن DPI)
```
روش: ارسال یک TLS ClientHello جعلی با SNI مجاز (مثل google.com)
     DPI آن را می‌بیند و اتصال را "مجاز" می‌داند
     سرور اصلی پکت جعلی را نادیده می‌گیرد (شماره SEQ اشتباه)
بهترین برای: دور زدن فیلترینگ مبتنی بر SNI
```

### 3. IP Spoofing
```
روش: ارسال پکت با IP جعلی برای گمراه کردن DPI
بهترین برای: مقاومت در برابر DPI پیشرفته
```

### 4. TCP / UDP
```
TCP: پایدار، مناسب برای اکثر کاربردها
UDP: سریع، مناسب برای وقتی که DPI فعال نیست
```

---

## 🔐 رمزنگاری | Encryption

| روش | سرعت | امنیت | ضد DPI |
|-----|------|-------|--------|
| ChaCha20-Poly1305 ⭐ | خیلی سریع | بالا | بله |
| AES-256-GCM | سریع (Hardware) | بالا | بله |
| XOR-Shift | خیلی سریع | پایین | خیر |
| Noise Padding | متوسط | بالا | بله ⭐ |
| TLS Mimicry | متوسط | بالا | بله ⭐ |

**توصیه**: `ChaCha20-Poly1305 + Noise Padding` برای بهترین نتیجه

---

## 📊 پنل مدیریت | Management Panel

پس از نصب، پنل از آدرس زیر در دسترس است:

```
http://SERVER_IP:PANEL_PORT
```

ویژگی‌های پنل:
- 📈 داشبورد با چارت‌های real-time
- 🔧 مدیریت تانل‌ها (افزودن، حذف، راه‌اندازی)
- 📋 لاگ‌های سیستم
- ⚙️ بهینه‌سازی سرور (BBR, sysctl)
- 🌐 رابط فارسی و انگلیسی
- 📱 طراحی responsive (موبایل + دسکتاپ)

---

## 🛠️ ساخت از سورس | Build from Source

### نصب Go

```bash
# دانلود Go 1.22+
wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

### Clone و Build

```bash
git clone https://github.com/Meytiz/hesar.git
cd hesar

# دانلود dependencies
make deps

# ساخت برای سیستم فعلی
make build

# ساخت برای لینوکس AMD64
make linux-amd64

# ساخت تمام نسخه‌ها
make release
```

### ساخت خروجی tar.gz

```bash
# ساخت تمام نسخه‌ها و آرشیو tar.gz
make package

# خروجی در پوشه build/
ls build/
# hesar-linux-amd64.tar.gz
# hesar-linux-arm64.tar.gz  
# hesar-linux-armv7.tar.gz
```

---

## 📦 آموزش خروجی tar.gz | How to Create tar.gz Release

### روش ۱ - استفاده از Makefile

```bash
cd hesar-go
make package
```

### روش ۲ - دستی

```bash
# ابتدا باینری‌ها را بسازید
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o build/hesar-linux-amd64 ./cmd/hesar/
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o build/hesar-linux-arm64 ./cmd/hesar/

# ایجاد tar.gz برای هر باینری
cd build
tar -czf hesar-linux-amd64.tar.gz hesar-linux-amd64
tar -czf hesar-linux-arm64.tar.gz hesar-linux-arm64

# یا یک آرشیو کامل با همه فایل‌ها
tar -czf hesar-v1.0.0-full.tar.gz \
  hesar-linux-amd64 \
  hesar-linux-arm64 \
  ../scripts/ \
  ../README.md

# بررسی آرشیو
tar -tvf hesar-v1.0.0-full.tar.gz

# استخراج
tar -xzf hesar-v1.0.0-full.tar.gz
```

### آپلود به GitHub Releases

```bash
# استفاده از GitHub CLI
gh release create v1.0.0 \
  build/hesar-linux-amd64.tar.gz \
  build/hesar-linux-arm64.tar.gz \
  --title "HESAR v1.0.0" \
  --notes "First stable release"
```

---

## 🖥️ دستورات | Commands

```bash
# نمایش راهنما
hesar --help

# مدیریت تانل‌ها
hesar tunnel start --config /etc/hesar/tunnels/NAME/config.json
hesar tunnel stop --name NAME
hesar tunnel list

# راه‌اندازی پنل
hesar panel --port 8443 --username admin --password YOUR_PASS

# بهینه‌سازی سیستم
hesar optimize --bbr --sysctl
```

---

## ⚙️ فایل کانفیگ | Config File

```json
{
  "mode": "iran",
  "protocol": "kcp",
  "tunnel": {
    "iran_ip": "185.x.x.x",
    "foreign_ip": "45.x.x.x",
    "connection_port": 34521,
    "config_ports": "80,443,8080"
  },
  "obfuscation": {
    "enabled": true,
    "method": "chacha20-poly1305",
    "key": "YOUR_32_CHAR_RANDOM_KEY_HERE",
    "noise_padding": true,
    "padding_size": 64
  },
  "kcp": {
    "crypt": "chacha20",
    "mode": "fast3",
    "mtu": 1350,
    "sndwnd": 2048,
    "rcvwnd": 2048,
    "datashard": 10,
    "parityshard": 3
  }
}
```

---

## 🔧 حذف | Uninstall

```bash
# فقط تانل‌ها
bash uninstall.sh tunnel

# فقط باینری (هسته)
bash uninstall.sh core

# حذف کامل
bash uninstall.sh all
```

---

## 📁 ساختار پروژه | Project Structure

```
hesar/
├── cmd/
│   └── hesar/
│       └── main.go              # نقطه ورود اصلی
├── internal/
│   ├── config/
│   │   └── config.go            # پارس کردن کانفیگ
│   ├── crypto/
│   │   └── obfuscate.go         # رمزنگاری و obfuscation
│   ├── tunnel/
│   │   └── tunnel.go            # منطق تانل ریورس
│   ├── protocol/
│   │   ├── kcp/
│   │   │   └── kcp.go           # پروتکل KCP
│   │   └── sni/
│   │       └── sni.go           # SNI Spoofing
│   ├── panel/
│   │   └── panel.go             # API وب پنل
│   └── logger/
│       └── logger.go            # سیستم لاگ
├── scripts/
│   ├── install.sh               # نصب اصلی
│   ├── install-iran.sh          # نصب سرور ایران
│   ├── install-foreign.sh       # نصب سرور خارج
│   └── uninstall.sh             # حذف
├── web/                         # فایل‌های پنل React (built)
├── Makefile                     # سیستم Build
├── go.mod
└── README.md
```

---

## 🐛 عیب‌یابی | Troubleshooting

### تانل وصل نمی‌شود

```bash
# بررسی وضعیت سرویس
systemctl status hesar-TUNNEL_NAME

# مشاهده لاگ‌های زنده
journalctl -u hesar-TUNNEL_NAME -f

# تست اتصال
nc -zv FOREIGN_IP CONN_PORT
```

### پنل باز نمی‌شود

```bash
# بررسی وضعیت پنل
systemctl status hesar-panel

# بررسی پورت
ss -tlnp | grep PANEL_PORT

# فایروال
ufw status
```

### BBR فعال نمی‌شود

```bash
# بررسی BBR
sysctl net.ipv4.tcp_congestion_control
modprobe tcp_bbr
```

---

## 📜 مجوز | License

این پروژه تحت مجوز MIT منتشر شده است. برای جزئیات فایل [LICENSE](LICENSE) را مطالعه کنید.

---

## 🤝 مشارکت | Contributing

Pull Request‌ها و Issue‌ها خوش‌آمد هستند.

---

<div align="center">
Made with ❤️ by <a href="https://github.com/Meytiz">Meytiz</a>
</div>
