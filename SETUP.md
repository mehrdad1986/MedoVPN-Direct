# 🚀 Quick Setup Guide

## Prerequisites
- Windows 10/11 or Linux
- Administrator/root access
- Cloudflare Account (free tier)

## 3-Minute Setup

### 1️⃣ Deploy Cloudflare Worker (2 minutes)

1. Visit https://dash.cloudflare.com/
2. Go to **Workers & Pages** → **Create Application** → **Create Worker**
3. Name it (example: `medo-gateway`)
4. Click **Quick Edit** or **Edit Code**
5. **Delete all existing code**
6. Copy everything from `cloudflare-worker/worker.js`
7. Paste into the editor
8. **Line 15**: Change this line:
   ```javascript
   const AUTH_KEY = "PUT_YOUR_PASSWORD_HERE";
   ```
   To:
   ```javascript
   const AUTH_KEY = "your-strong-random-password-here";
   ```
9. Click **Save and Deploy**
10. **Copy your worker URL** (example: `https://medo-gateway.yourname.workers.dev`)

### 2️⃣ Run the Client (30 seconds)

#### Windows
1. Download `medovpn-direct-windows-amd64.exe` from [Releases](../../releases)
2. Double-click to run
3. GUI opens automatically at http://127.0.0.1:5560

#### Linux
```bash
wget https://github.com/YOUR_USERNAME/MedoVPN-Direct/releases/latest/download/medovpn-direct-linux-amd64
chmod +x medovpn-direct-linux-amd64
./medovpn-direct-linux-amd64
```

### 3️⃣ Configure the Client (30 seconds)

In the web GUI that opened:

1. **Worker URL**: Paste your Cloudflare Worker URL from Step 1
2. **Gateway Password**: Enter the password you set in Step 1
3. Click **"Install CA Certificate"** and confirm
4. Click **"Start Proxy"**

### 4️⃣ Configure Your Browser

**Firefox (Recommended):**
1. Settings → Network Settings → **Manual proxy configuration**
2. HTTP Proxy: `127.0.0.1`
3. Port: `5555`
4. ✅ Check "Also use this proxy for HTTPS"
5. Click OK

**Chrome / Edge:**
1. Install [Proxy SwitchyOmega](https://chrome.google.com/webstore/detail/proxy-switchyomega/)
2. Create new profile → HTTP proxy → Server: `127.0.0.1` → Port: `5555`
3. Apply and activate the profile

## ✅ Test It

1. Visit https://www.google.com
2. If it loads, you're connected! 🎉

You can also test the worker directly:
- Visit `https://your-worker.yourname.workers.dev/health`
- Expected: `MedoVPN Gateway is online.`

## 🔧 Troubleshooting

### "Certificate not trusted" error
**Solution:**
1. Click "Install CA Certificate" again in the GUI
2. Windows: Confirm the security prompt
3. Restart your browser

### "Cannot connect to worker" error
**Solution:**
1. Check the worker URL is correct (copy-paste from Cloudflare dashboard)
2. Check the password matches what you set in `AUTH_KEY`
3. Test: Visit `https://your-worker.workers.dev/` - you should see a website (not an error)

### Browser shows "Secure Connection Failed"
**Solution:**
1. The CA certificate wasn't installed correctly
2. Re-install from GUI
3. **Windows**: Check it's in "Trusted Root Certification Authorities"
4. **Linux**: Run `sudo update-ca-certificates` after install

### Slow performance
**Optimization:**
1. Enable DoH (DNS over HTTPS) in GUI → Advanced
2. Enable hedge requests for lower latency
3. Enable connection rotation

## 📊 Performance Tips

For best performance:
- ✅ Enable **DoH** (DNS over HTTPS)
- ✅ Enable **Hedge Requests** (reduces latency)
- ✅ Enable **Connection Rotation** (avoids blocking)
- ✅ Use **Firefox** (better proxy support than Chrome)

## 🎥 Video Streaming

MedoVPN Direct is optimized for video streaming:
- YouTube ✅
- Vimeo ✅
- Other video sites ✅

If you experience buffering:
1. Check latency in the GUI (should be < 300ms)
2. Enable hedge requests
3. Increase connection pool size (Advanced → Max connections: 20)

## 🎉 You're Done!

You now have a fast, direct censorship-resistant proxy. Enjoy free internet access!

## 📚 More Help

- [Full Documentation](README.md)
- [GitHub Issues](../../issues)
- [Discussions](../../discussions)

---

**Stay safe, stay connected! 🌐**
