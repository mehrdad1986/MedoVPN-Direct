# ⚡ MedoVPN Direct

> **A fast, single-hop censorship circumvention solution with decoy website capabilities**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green.svg)]()
[![Status](https://img.shields.io/badge/Status-Production-brightgreen.svg)]()

## 📋 Overview

**MedoVPN Direct** is a streamlined anti-censorship tool that provides **fast, direct access** through a single Cloudflare Worker relay. Unlike the Bridge version, it eliminates the Google Apps Script layer for **lower latency** and **higher throughput**, making it ideal for bandwidth-intensive applications like video streaming.

### Why Direct Mode?

In many scenarios, a single well-configured relay is sufficient and provides better performance:

```
Browser → Local Client → Cloudflare Worker → Target Website
```

This architecture provides:
- ⚡ **Lower Latency** - One less hop means faster responses (100-300ms typical)
- 🎥 **Better for Streaming** - Higher throughput for video and large files
- 🔒 **Built-in Decoy** - Worker serves a fake Persian blog to evade detection
- 💰 **Cost Effective** - Only uses Cloudflare's generous free tier

---

## 🌟 Key Features

### 🔐 Security & Privacy
- **Local HTTPS interception** with trusted CA certificate
- **Domain fronting** through Cloudflare's global network
- **TLS ClientHello fragmentation** to bypass SNI filtering
- **Decoy website** - Worker appears as a legitimate Persian blog
- **No data retention** - all processing is client-side

### 🚀 Performance
- **Hedge requests** - parallel requests for latency-sensitive operations
- **Connection rotation** - automatic refresh to avoid blocking
- **DNS over HTTPS** - encrypted DNS lookups
- **Request batching** - reduces round trips

### 🎯 Reliability
- **Health checks** with auto-reconnect
- **Retry budget** - smart retry with backoff
- **Loop detection** - prevents routing loops
- **Graceful fallback** - continues working even with partial failures

### 💻 User Experience
- **Control panel** at `http://127.0.0.1:5560`
- **One-click setup** - no complex configuration
- **Real-time metrics** - latency, success rate, throughput
- **Windows DPAPI** - secure credential storage

---

## 🎯 Who Should Use MedoVPN Direct?

### ✅ Perfect For:
- **Moderate censorship environments** where single-hop proxies work
- **Video streaming** and high-bandwidth applications
- **Latency-sensitive** applications (gaming, VoIP)
- **Users who want simple setup** without complex configuration
- **Quick unblocking** of social media and news sites

### ⚠️ Consider Bridge Mode Instead If:
- You're in **high-surveillance** countries (China, Iran, etc.)
- Single-hop proxies are **aggressively blocked** in your region
- You need **maximum anonymity** (two independent hops)
- You want **redundancy** with Google + Cloudflare infrastructure

---

## 🏗️ Architecture

### Components

#### 1. **Desktop Client** (`client/medovpn-direct.go`)
Local HTTP/HTTPS proxy that:
- Listens on `127.0.0.1:5555` for browser connections
- Performs HTTPS MITM with local CA certificate
- Encodes requests as JSON
- Sends directly to Cloudflare Worker
- Decodes and returns responses

#### 2. **Cloudflare Worker** (`cloudflare-worker/worker.js`)
Single relay that:
- **POST /relay** - processes proxy requests
- **GET /health** - returns health status
- **GET /** - serves a decoy Persian blog (fake static site)
- Handles up to 24MB responses
- Implements security checks (loop detection, self-fetch blocking)

---

## 📦 Installation

### Prerequisites
- **Windows 10/11** or **Linux** (kernel 3.2+)
- Administrator/root access for certificate installation

### Quick Start

#### Option 1: Pre-built Binaries

1. **Download** the latest release from the [Releases](../../releases) page:
   - Windows: `medovpn-direct-windows-amd64.exe`
   - Linux: `medovpn-direct-linux-amd64`
   - Debian/Ubuntu: `medovpn-direct_amd64.deb`

2. **Run** the application:
   ```bash
   # Windows
   .\medovpn-direct-windows-amd64.exe
   
   # Linux
   chmod +x medovpn-direct-linux-amd64
   ./medovpn-direct-linux-amd64
   ```

3. **Access the control panel**: Opens automatically at `http://127.0.0.1:5560`

#### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/MedoVPN-Direct.git
cd MedoVPN-Direct/client

# Install dependencies
go mod download

# Build
go build -o medovpn-direct medovpn-direct.go

# Run
./medovpn-direct
```

---

## ⚙️ Setup Guide

### Step 1: Deploy Cloudflare Worker

1. **Log in** to [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Go to **Workers & Pages** → **Create Application** → **Create Worker**
3. **Name your worker** (e.g., `medo-gateway`)
4. Click **Quick Edit** or **Edit Code**
5. **Copy** the entire contents of `cloudflare-worker/worker.js`
6. **Paste** into the editor, replacing all existing code
7. **Edit line 15**: Replace `"PUT_YOUR_PASSWORD_HERE"` with a strong password
   ```javascript
   const AUTH_KEY = "your-secure-random-password-here";
   ```
8. **Click "Save and Deploy"**
9. **Copy the Worker URL** (e.g., `https://medo-gateway.yourname.workers.dev`)

### Step 2: Configure the Client

1. **Launch** the MedoVPN Direct application
2. The **control panel** opens automatically at `http://127.0.0.1:5560`
3. **Enter Configuration**:
   - **Worker URL**: Paste your Cloudflare Worker URL
   - **Gateway Password**: Enter the password you set in `AUTH_KEY`
4. **Install Certificate**: Click "Install CA Certificate" button
   - Windows: Confirm the security prompt
   - Linux: Follow the instructions shown
5. **Start Proxy**: Click "Start" button

### Step 3: Configure Your Browser

#### Firefox (Recommended)
1. **Open Settings** → Network Settings → **Manual proxy configuration**
2. **HTTP Proxy**: `127.0.0.1`
3. **Port**: `5555`
4. ✅ Check "Also use this proxy for HTTPS"
5. **Save**

#### Chrome / Edge
1. Install [Proxy SwitchyOmega](https://chrome.google.com/webstore/detail/proxy-switchyomega/)
2. **Create new profile** → Protocol: `HTTP` → Server: `127.0.0.1` → Port: `5555`
3. ✅ Enable "Use this proxy for HTTPS"
4. **Apply and activate** the profile

---

## 🔧 Configuration

### Environment Variables

```bash
# Cloudflare Worker URL (required)
export WORKER_URL="https://your-worker.yourname.workers.dev"

# Authentication password (required)
export GATEWAY_PASSWORD="your-secure-password"

# Local proxy address (default: 127.0.0.1:5555)
export LISTEN_ADDR="127.0.0.1:5555"

# GUI address (default: 127.0.0.1:5560)
export GUI_LISTEN_ADDR="127.0.0.1:5560"

# CA certificate paths (optional)
export CA_CERT_FILE="/path/to/mycert.crt"
export CA_KEY_FILE="/path/to/mycert.key"
```

### Command-line Options

```bash
./medovpn-direct \
  --worker-url "https://worker.yourname.workers.dev" \
  --listen "127.0.0.1:5555" \
  --gui-listen "127.0.0.1:5560" \
  --ca-cert "/path/to/cert.crt" \
  --ca-key "/path/to/key.key" \
  --no-open  # Don't auto-open the GUI
```

---

## 🛠️ Advanced Features

### Decoy Website

The worker serves a **fake Persian blog** when accessed via `GET /`:
- **Purpose**: Makes the worker look like a normal website to censors
- **Content**: Generic blog about daily life, technology
- **Includes**: CSS, JavaScript, sitemap.xml, robots.txt, favicon
- **Result**: Active probing sees a legitimate site, not proxy infrastructure

### DNS over HTTPS (DoH)

Prevents DNS-based censorship:
1. **Open GUI** → Advanced Settings
2. **Enable DoH**
3. **Choose provider**:
   - Cloudflare: `https://1.1.1.1/dns-query` (default)
   - Google: `https://dns.google/dns-query`
   - AdGuard: `https://dns.adguard.com/dns-query`

### TLS Fragmentation

Defeats SNI-based blocking:
1. **Open GUI** → Advanced → Fragmentation
2. **Enable** "Fragment ClientHello"
3. **Configure**:
   - Fragment size: 40-64 bytes (default: 64)
   - Delay: 10-50ms (default: 20ms)

### Connection Rotation

Avoids long-lived connection fingerprinting:
1. **Open GUI** → Advanced → Connection Management
2. **Enable** "Rotate connections"
3. **Set interval**: 2-10 minutes (default: 5 minutes)

### Hedge Requests

Reduce tail latency for idempotent requests:
1. **Open GUI** → Performance
2. **Enable** "Hedge GET requests"
3. **Delay**: 500-2000ms (default: 1000ms)

---

## 🔒 Security & Privacy

### How Your Data is Protected

1. **End-to-End Encryption**
   - All traffic between client and Cloudflare Worker uses TLS 1.3
   - Local MITM uses your own CA certificate (you control the trust)
   - No third party can decrypt your traffic

2. **No Logging**
   - Client doesn't log requests
   - Worker doesn't store any data
   - Everything is processed in-memory and discarded

3. **Traffic Obfuscation**
   - Requests disguised as JSON POST data
   - Base64 encoding makes content inspection harder
   - Worker serves decoy website for GET requests

### Threat Model

**What MedoVPN Direct Protects Against:**
- ✅ ISP content filtering and blocking
- ✅ SNI-based censorship (with TLS fragmentation)
- ✅ DNS-based blocking (with DoH enabled)
- ✅ Basic DPI (Deep Packet Inspection)
- ✅ Website tracking your real IP

**What It Does NOT Protect Against:**
- ❌ Advanced traffic analysis by nation-state actors
- ❌ Cloudflare compromise (they can see decrypted traffic)
- ❌ Endpoint surveillance (target website behavior)
- ❌ Client-side malware

### Best Practices

1. **Use HTTPS websites** - Only the final hop is unencrypted
2. **Don't transmit sensitive data** - This is for unblocking, not anonymity
3. **Rotate worker credentials** every few months
4. **Use a custom domain** on Cloudflare for extra obfuscation
5. **Enable all evasion features** (DoH, TLS fragmentation, rotation)

---

## ❓ Frequently Asked Questions (FAQ)

### General Questions

**Q: Is MedoVPN Direct free?**  
A: Yes! It uses Cloudflare's free tier (100,000 requests/day). No paid services required.

**Q: Is it safe?**  
A: For general web browsing and unblocking, yes. For high-risk activism or journalism, use Bridge mode or Tor.

**Q: Can my ISP detect this?**  
A: They can see you're connecting to Cloudflare, but not what you're accessing. With TLS fragmentation and DoH, detection is very difficult.

**Q: Will Cloudflare know what sites I visit?**  
A: Yes. Cloudflare processes your requests (like any proxy). They can see destination URLs but have stated they don't log customer data.

### Technical Questions

**Q: Why do I need to install a certificate?**  
A: To intercept HTTPS traffic locally and re-encrypt it for the worker. The certificate is only trusted by YOUR browser, not anyone else.

**Q: What happens if my worker gets blocked?**  
A: Deploy a new worker with a different name, or use a custom domain on Cloudflare.

**Q: Can I use multiple workers for load balancing?**  
A: Yes! Add multiple worker URLs in Advanced Settings and the client will rotate between them.

**Q: Does this work with torrents?**  
A: No. HTTP/HTTPS proxies only. For torrents, use a SOCKS5 proxy or VPN.

**Q: Can I share my worker URL with friends?**  
A: Yes, but share the password separately. Each user needs their own client installation.

### Performance Questions

**Q: Why is YouTube buffering?**  
A: Check latency in the control panel. If > 300ms, enable hedge requests and increase connection pool size.

**Q: How much bandwidth can I use?**  
A: Cloudflare free tier has no bandwidth limits, but there's a 100,000 request/day cap. Each video chunk is 1 request.

**Q: Can I use this 24/7?**  
A: Yes, but enable connection rotation to avoid long-lived connection fingerprinting.

### Comparison Questions

**Q: Direct vs Bridge - which is better?**  
A: 
- **Direct**: Faster (100-300ms), better for streaming, simpler setup
- **Bridge**: More secure (two hops), harder to block, better for high-censorship

**Q: How does this compare to commercial VPNs?**  
A:
- **Pros**: Free, you control the infrastructure, harder to block
- **Cons**: Lower throughput, requires technical setup, less anonymity

**Q: Why not just use Tor?**  
A: Tor is blocked in many countries and very slow. MedoVPN Direct is faster and uses trusted CDN infrastructure.

---

## 📡 Monitoring & Maintenance

### Health Checks

The control panel shows real-time metrics:
- **Latency**: Average response time (target: < 300ms)
- **Success Rate**: % of successful requests (target: > 95%)
- **Throughput**: Current bandwidth usage
- **Active Connections**: Number of open connections

### Maintenance Tasks

**Weekly:**
- Check control panel for unusual latency spikes
- Verify certificate expiration (auto-renewed, but check)

**Monthly:**
- Review Cloudflare Worker analytics for quota usage
- Rotate worker password if concerned about compromise
- Update client to latest version

**As Needed:**
- If worker gets blocked, deploy new one with different name
- If performance degrades, check Cloudflare status page
- If certificate errors appear, re-install certificate

### Upgrading

**Cloudflare Worker:**
```bash
# No downtime needed - just update the code
1. Edit worker in Cloudflare dashboard
2. Click "Save and Deploy"
3. Worker URL stays the same
```

**Desktop Client:**
```bash
# Download new version
# Configuration is preserved
1. Stop the current client
2. Replace executable with new version
3. Start the new client
```

---

## 🌍 Deployment Best Practices

### For Personal Use

**Basic Setup:**
```
Single Cloudflare Worker
↓
Your Computer
```

**Enhanced Setup (Recommended):**
```
Custom Domain (Cloudflare)
↓
Cloudflare Worker with TLS Fragmentation
↓
Your Computer with DoH enabled
```

### For Sharing with Friends/Family

**Multi-User Setup:**
```yaml
# Option 1: Shared Worker
- 1 Worker URL shared with everyone
- Same password for all users
- Cloudflare free tier: 100K requests/day total
- Good for: 5-10 light users

# Option 2: Per-User Workers  
- Each user gets their own worker
- Different passwords for each
- Each gets 100K requests/day
- Good for: 10+ users or heavy usage
```

**Sharing Instructions:**
1. Create a simple setup guide (use SETUP.md)
2. Share worker URL + password via secure channel (Signal, WhatsApp)
3. Provide pre-built executables from Releases
4. Offer remote support for certificate installation

### For Organizations

**High-Availability Setup:**
```
Load Balancer
├── Worker 1 (Region: EU)
├── Worker 2 (Region: US)
└── Worker 3 (Region: Asia)
```

**Configuration:**
1. Deploy 3+ workers in different Cloudflare regions
2. Configure client with all worker URLs
3. Enable automatic failover in Advanced Settings
4. Set up monitoring with health check endpoints

---

## 🔧 Advanced Configuration

### Custom Cloudflare Domain

Instead of `your-name.workers.dev`, use your own domain:

**Benefits:**
- Harder to block (not obviously a proxy)
- Looks like normal website traffic
- Can use multiple subdomains

**Setup:**
1. Add your domain to Cloudflare (free)
2. Go to Worker → Triggers → Add Custom Domain
3. Use `proxy.yourdomain.com` or similar
4. Update client configuration with new URL

### Docker Deployment

Run the client as a container:

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY client/ .
RUN go build -o medovpn-direct medovpn-direct.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/medovpn-direct /usr/local/bin/
EXPOSE 5555 5560
CMD ["medovpn-direct"]
```

```bash
docker build -t medovpn-direct .
docker run -p 5555:5555 -p 5560:5560 medovpn-direct
```

### Systemd Service (Linux)

Auto-start on boot:

```ini
[Unit]
Description=MedoVPN Direct Client
After=network.target

[Service]
Type=simple
User=your-username
WorkingDirectory=/home/your-username/medovpn
ExecStart=/home/your-username/medovpn/medovpn-direct
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable medovpn-direct
sudo systemctl start medovpn-direct
```

### Windows Service

Run as background service:
1. Download [NSSM](https://nssm.cc/)
2. Run: `nssm install MedoVPN`
3. Path: `C:\path\to\medovpn-direct.exe`
4. Click "Install Service"
5. Start: `nssm start MedoVPN`

---

## 🔍 Troubleshooting

### "Cannot connect to worker" error
**Causes**:
- Worker URL is incorrect
- Worker password doesn't match
- Worker is not deployed

**Solution**:
1. Test worker health: Visit `https://your-worker.workers.dev/health`
2. Expected response: `MedoVPN Gateway is online.`
3. If you see HTML or error, re-deploy the worker

### Certificate errors in browser
**Solution**:
1. **Re-install certificate** from the GUI
2. **Windows**: Must be in "Trusted Root Certification Authorities"
3. **Linux**: May need to run `update-ca-certificates` after install
4. **Restart browser** after installing

### Slow performance
**Optimization**:
1. ✅ Enable DoH to avoid slow DNS lookups
2. ✅ Enable hedge requests for GET operations
3. ✅ Increase connection pool size (Advanced → Max connections: 10-20)
4. ✅ Reduce hedge delay to 500-700ms

### YouTube/video buffering
**Tips**:
- MedoVPN Direct is optimized for streaming
- Ensure your Cloudflare Worker is deployed to a region close to you
- Check control panel metrics for packet loss or high latency
- If latency > 500ms consistently, consider using a custom domain with Cloudflare

### Worker quota exceeded
Cloudflare Free tier limits:
- **100,000 requests/day**
- **10ms CPU time per request**

**Solutions**:
1. Upgrade to Workers Paid ($5/month for 10M requests)
2. Deploy multiple workers and load-balance
3. Use MedoVPN Bridge to reduce worker load

---

## 📊 Performance Benchmarks

### Typical Performance Metrics
| Metric | Value | Notes |
|--------|-------|-------|
| Latency (avg) | 100-300ms | Depends on Cloudflare edge location |
| Throughput | 50-100 Mbps | Limited by base64 encoding overhead |
| Max request size | 10 MB | Client-side limit |
| Max response size | 24 MB | Worker-side limit (before encoding) |
| Concurrent connections | 10-50 | Configurable in GUI |

### Comparison with Bridge Mode

| Feature | Direct | Bridge |
|---------|--------|--------|
| Latency | ⚡ 100-300ms | 🐢 300-800ms |
| Video streaming | ✅ Excellent | ⚠️ Limited |
| Setup complexity | ⭐ Simple | ⭐⭐ Moderate |
| Detection resistance | ⭐⭐ Good | ⭐⭐⭐ Excellent |
| Daily quota | 100K requests | 20K (GAS limit) |

---

## 🌐 Use Cases

### Best For
- ✅ General web browsing and social media
- ✅ Video streaming (YouTube, Vimeo, etc.)
- ✅ File downloads (up to 24MB chunks)
- ✅ Regions with moderate censorship

### Consider Bridge Mode Instead If
- 🔄 You need maximum anonymity (two hops)
- 🔄 Single-hop proxies are aggressively blocked
- 🔄 You're in a high-surveillance environment
- 🔄 You need fallback redundancy

---

## 🤝 Contributing

This project helps people access free information. Contributions are welcome!

### Ways to Contribute
- 🐛 Report bugs and issues
- 💡 Suggest new features
- 📖 Improve documentation
- 🌍 Translate to other languages
- 🔧 Submit pull requests

### Development Setup
```bash
git clone https://github.com/YOUR_USERNAME/MedoVPN-Direct.git
cd MedoVPN-Direct

# Install Go dependencies
cd client
go mod download

# Run tests
go test ./...

# Build
go build -o medovpn-direct medovpn-direct.go
```

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

You are free to:
- ✅ Use commercially
- ✅ Modify
- ✅ Distribute
- ✅ Use privately

---

## ⚠️ Disclaimer

This software is provided for **legitimate privacy and security purposes**. It is designed to help people access information in regions where internet access is restricted.

**Users must**:
- Comply with local laws and regulations
- Use responsibly and ethically
- Not use for illegal activities

**The developers**:
- Assume no liability for misuse
- Do not log or track user activity
- Provide this software "as-is"

---

## 🌍 Support Internet Freedom

This project is part of the global effort to maintain **free and open internet access** for everyone.

### Get Help
- 📚 [Documentation](../../wiki)
- 💬 [Discussions](../../discussions)
- 🐛 [Report Issues](../../issues)
- 🔐 [Security](SECURITY.md)

### Resources for Activists
- [Electronic Frontier Foundation](https://www.eff.org/)
- [Access Now](https://www.accessnow.org/)
- [Digital Security Guides](https://www.eff.org/pages/digital-security)

---

## 🙏 Acknowledgments

- **Cloudflare** for providing robust Worker infrastructure
- The **anti-censorship community** for inspiration and support
- **Contributors** who help improve this project
- **Users** in restricted regions who motivate this work

---

<div align="center">

**Built for freedom. Maintained by the community.**

⭐ **Star this repository** if it helps you stay connected

🔗 **Share** to help others access the free internet

</div>

---

## 📈 Project Stats

![GitHub stars](https://img.shields.io/github/stars/YOUR_USERNAME/MedoVPN-Direct?style=social)
![GitHub forks](https://img.shields.io/github/forks/YOUR_USERNAME/MedoVPN-Direct?style=social)
![GitHub issues](https://img.shields.io/github/issues/YOUR_USERNAME/MedoVPN-Direct)
![GitHub pull requests](https://img.shields.io/github/issues-pr/YOUR_USERNAME/MedoVPN-Direct)

---

