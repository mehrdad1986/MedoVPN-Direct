# 📦 Releases

Pre-compiled binaries for MedoVPN Direct will be available here.

## Download

Visit the [Releases page](https://github.com/YOUR_USERNAME/MedoVPN-Direct/releases) to download:

- **Windows**: `medovpn-direct-windows-amd64.exe`
- **Linux**: `medovpn-direct-linux-amd64`
- **Debian/Ubuntu**: `medovpn-direct_amd64.deb`

## Build from Source

```bash
cd client
go build -o medovpn-direct medovpn-direct.go
```

## Verify Downloads

All releases are signed with GPG. Import the public key and verify:

```bash
# Import public key
gpg --import public-key.asc

# Verify signature
gpg --verify medovpn-direct-linux-amd64.sig medovpn-direct-linux-amd64
```
