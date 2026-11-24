// MedoVPN: local HTTP/HTTPS proxy that relays browser traffic through a
// Cloudflare Worker (Windows client).
//
// The proxy listens on loopback. Plain HTTP requests are relayed to the
// Gateway Worker as JSON. HTTPS CONNECT tunnels are terminated locally using a
// CA that the user trusts, and each decrypted request is relayed the same way.
//
// Optional transport features, configured in the control panel:
//   - ClientHello fragmentation on new Worker connections (fragmentingConn)
//   - Connection-age rotation of Worker connections (agedConn, attemptRelay)
//   - Hedged requests for idempotent methods (relayWithHedge)
//   - Bounded retries limited by a retry budget (sendRelayPayload, retryBudget)
//   - DNS over HTTPS for the proxy's own dials (DoHResolver)
//
// The control panel is served on loopback only and requires a per-session
// token. The Gateway password and Cloudflare API token are protected with
// Windows DPAPI.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// MedoVPN: local HTTP/HTTPS proxy that relays browser traffic through a
// Cloudflare Worker (Windows client).
//
// The proxy listens on loopback. Plain HTTP requests are relayed to the
// Gateway Worker as JSON. HTTPS CONNECT tunnels are terminated locally using a
// CA that the user trusts, and each decrypted request is relayed the same way.
//
// Optional transport features, configured in the control panel:
//   - ClientHello fragmentation on new Worker connections (fragmentingConn)
//   - Connection-age rotation of Worker connections (agedConn, attemptRelay)
//   - Hedged requests for idempotent methods (relayWithHedge)
//   - Bounded retries limited by a retry budget (sendRelayPayload, retryBudget)
//   - DNS over HTTPS for the proxy's own dials (DoHResolver)
//
// The control panel is served on loopback only and requires a per-session
// token. The Gateway password and Cloudflare API token are protected with
// Windows DPAPI.

func main() {
	logs := newAppLogBuffer(maxUILogEntries)
	log.SetFlags(0)
	log.SetOutput(io.MultiWriter(safeWriter{w: os.Stderr}, appLogWriter{buffer: logs}))
	defaultCert, defaultKey := defaultCAPaths()
	settingsPath, err := settingsFilePath()
	if err != nil {
		log.Fatalf("find settings directory: %v", err)
	}
	listenFlag := flag.String("listen", "", "default local browser proxy address")
	workerURLFlag := flag.String("worker-url", "", "Cloudflare Worker HTTPS URL")
	caCertFlag := flag.String("ca-cert", "", "local HTTPS inspection CA certificate path")
	caKeyFlag := flag.String("ca-key", "", "matching local HTTPS inspection CA key path")
	guiListenFlag := flag.String("gui-listen", envOr("GUI_LISTEN_ADDR", defaultGUIAddress), "local GUI address")
	noOpenFlag := flag.Bool("no-open", false, "do not open the GUI in a browser")
	settingsFileFlag := flag.String("settings-file", settingsPath, "local non-secret settings file")
	flag.Parse()

	defaults := proxySettings{
		WorkerURL:             defaultWorkerURL,
		ListenAddress:         defaultListenAddress,
		CACertPath:            defaultCert,
		CAKeyPath:             defaultKey,
		CloudflareAccountID:   strings.TrimSpace(os.Getenv("CLOUDFLARE_ACCOUNT_ID")),
		CloudflareWorker:      envOr("CLOUDFLARE_WORKER_NAME", "gateway"),
		CloudflareFetchWorker: envOr("CLOUDFLARE_FETCH_WORKER_NAME", "fetch"),
	}
	// Precedence: command-line flags > saved settings > environment > built-in.
	// The environment is applied first so that values saved in the control
	// panel are not silently overridden by a stale environment variable.
	if value := strings.TrimSpace(os.Getenv("WORKER_URL")); value != "" {
		defaults.WorkerURL = value
	}
	if value := strings.TrimSpace(os.Getenv("LISTEN_ADDR")); value != "" {
		defaults.ListenAddress = value
	}
	if value := strings.TrimSpace(os.Getenv("CA_CERT_FILE")); value != "" {
		defaults.CACertPath = value
	}
	if value := strings.TrimSpace(os.Getenv("CA_KEY_FILE")); value != "" {
		defaults.CAKeyPath = value
	}
	if value := strings.TrimSpace(os.Getenv("CLOUDFLARE_ACCOUNT_ID")); value != "" {
		defaults.CloudflareAccountID = value
	}
	if value := strings.TrimSpace(os.Getenv("CLOUDFLARE_WORKER_NAME")); value != "" {
		defaults.CloudflareWorker = value
	}
	if value := strings.TrimSpace(os.Getenv("CLOUDFLARE_FETCH_WORKER_NAME")); value != "" {
		defaults.CloudflareFetchWorker = value
	}
	loadSavedSettings(*settingsFileFlag, &defaults)

	if *listenFlag != "" {
		defaults.ListenAddress = *listenFlag
	}
	if *workerURLFlag != "" {
		defaults.WorkerURL = *workerURLFlag
	}
	if *caCertFlag != "" {
		defaults.CACertPath = *caCertFlag
	}
	if *caKeyFlag != "" {
		defaults.CAKeyPath = *caKeyFlag
	}

	// Apply configuration defaults
	applyConfigDefaults(&defaults)

	if err := validateLoopbackAddress(*guiListenFlag); err != nil {
		log.Fatalf("GUI address: %v", err)
	}
	guiListener, err := net.Listen("tcp", *guiListenFlag)
	if err != nil {
		log.Fatalf("start local GUI at %s: %v", *guiListenFlag, err)
	}
	defer guiListener.Close()

	uiToken, err := randomToken()
	if err != nil {
		log.Fatalf("create GUI session token: %v", err)
	}
	quit := make(chan struct{}, 1)
	controller := &proxyController{logs: logs}
	tokenPath, err := cloudflareTokenFilePath()
	if err != nil {
		log.Fatalf("find Cloudflare token config directory: %v", err)
	}
	gatewayKeyPath, err := gatewayKeyFilePath()
	if err != nil {
		log.Fatalf("find Worker password config directory: %v", err)
	}
	initialGatewayKey := strings.TrimSpace(os.Getenv("CLIENT_AUTH_KEY"))
	if initialGatewayKey == "" {
		initialGatewayKey = loadGatewayKey(gatewayKeyPath)
	}
	ui := &controlUI{
		controller:          controller,
		uiToken:             uiToken,
		allowedHost:         guiListener.Addr().String(),
		defaults:            defaults,
		initialGatewayKey:   initialGatewayKey,
		gatewayKeyPath:      gatewayKeyPath,
		settingsFile:        *settingsFileFlag,
		cloudflareToken:     loadCloudflareToken(tokenPath),
		cloudflareTokenPath: tokenPath,
		logs:                logs,
		tail:                newCloudflareTailGroup(logs),
	}
	guiServer := &http.Server{
		Addr:              guiListener.Addr().String(),
		Handler:           ui,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := guiServer.Serve(guiListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("local GUI stopped: %v", err)
			select {
			case quit <- struct{}{}:
			default:
			}
		}
	}()

	guiURL := "http://" + guiListener.Addr().String() + "/"
	log.Printf("MedoVPN control panel: %s", guiURL)
	if !*noOpenFlag {
		openSystemBrowser(guiURL)
	}

	// Handle both SIGINT and SIGTERM
	stopSignal, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-stopSignal.Done():
	case <-quit:
	}
	controller.stop()
	ui.tail.Stop()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = guiServer.Shutdown(shutdown)
}

// safeWriter wraps a writer and swallows its errors, so an invalid or closed
// stderr (common for GUI-subsystem Windows builds) cannot stop log delivery to
// the other writers in an io.MultiWriter.
type safeWriter struct {
	w io.Writer
}

func (s safeWriter) Write(p []byte) (int, error) {
	if s.w != nil {
		_, _ = s.w.Write(p)
	}
	return len(p), nil
}

func openSystemBrowser(address string) {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", address)
	case "darwin":
		command = exec.Command("open", address)
	default:
		command = exec.Command("xdg-open", address)
	}
	if err := command.Start(); err != nil {
		log.Printf("open the MedoVPN GUI at %s", address)
		return
	}
	go func() { _ = command.Wait() }()
}

type proxySettings struct {
	WorkerURL             string `json:"workerURL"`
	ListenAddress         string `json:"listenAddress"`
	CACertPath            string `json:"caCertPath"`
	CAKeyPath             string `json:"caKeyPath"`
	WorkerCACertPath      string `json:"workerCACertPath"`
	CloudflareAccountID   string `json:"cloudflareAccountId"`
	CloudflareWorker      string `json:"cloudflareWorker"`
	CloudflareFetchWorker string `json:"cloudflareFetchWorker"`

	// DPI Evasion Toggles (capabilities 1-3)
	EnableHedging            bool `json:"enableHedging"`
	EnableConnectionRotation bool `json:"enableConnectionRotation"`
	EnableFragmentation      bool `json:"enableFragmentation"`
	// DPIConfigured is written by builds before settingsVersion existed. It is
	// read only to migrate those files and is never written again.
	DPIConfigured   bool `json:"dpiConfigured,omitempty"`
	SettingsVersion int  `json:"settingsVersion"` // see settingsVersion

	// Hedging configuration
	HedgeDelayMs int `json:"hedgeDelayMs"` // milliseconds before firing hedge request

	// Connection rotation configuration
	ConnectionMaxAgeSec int `json:"connectionMaxAgeSec"` // seconds before rotating connection

	// Fragmentation configuration
	FragmentDelayMs int `json:"fragmentDelayMs"` // milliseconds between fragments
	FragmentPieces  int `json:"fragmentPieces"`  // 2-6 pieces to split ClientHello into
	FragmentSizeMin int `json:"fragmentSizeMin"` // minimum fragment size in bytes
	FragmentSizeMax int `json:"fragmentSizeMax"` // maximum fragment size in bytes

	// Retry configuration
	EnableRetry       bool    `json:"enableRetry"`
	MaxRetryAttempts  int     `json:"maxRetryAttempts"`
	RetryStrategy     string  `json:"retryStrategy"`     // "immediate", "fixed", "exponential"
	InitialBackoffMs  int     `json:"initialBackoffMs"`  // milliseconds
	MaxBackoffMs      int     `json:"maxBackoffMs"`      // milliseconds
	BackoffMultiplier float64 `json:"backoffMultiplier"` // for exponential backoff
	RetryOnTimeout    bool    `json:"retryOnTimeout"`

	// Connection pool configuration
	MaxConcurrentRequests int  `json:"maxConcurrentRequests"` // 0 = unlimited
	EnableConnectionPool  bool `json:"enableConnectionPool"`  // Master enable/disable for pool settings
	EnableConnectionReuse bool `json:"enableConnectionReuse"`
	MaxIdleConns          int  `json:"maxIdleConns"`
	MaxIdleConnsPerHost   int  `json:"maxIdleConnsPerHost"`
	IdleConnTimeoutSec    int  `json:"idleConnTimeoutSec"` // seconds

	// Health check configuration
	EnableHealthCheck   bool   `json:"enableHealthCheck"`   // Master enable/disable for health checks
	HealthCheckMode     string `json:"healthCheckMode"`     // "endpoint", "disabled"
	HealthCheckInterval int    `json:"healthCheckInterval"` // seconds between checks
	HealthCheckTimeout  int    `json:"healthCheckTimeout"`  // seconds

	// CDN edge IP override
	CDNEdgeIP string `json:"cdnEdgeIP"` // optional: dial this IP while keeping SNI/Host

	// Timeouts configuration
	DialTimeoutMs           int `json:"dialTimeoutMs"`           // milliseconds
	TLSHandshakeTimeoutMs   int `json:"tlsHandshakeTimeoutMs"`   // milliseconds
	ResponseHeaderTimeoutMs int `json:"responseHeaderTimeoutMs"` // milliseconds
	RequestTimeoutMs        int `json:"requestTimeoutMs"`        // milliseconds

	// ALPN configuration
	ALPNProtocols string `json:"alpnProtocols"` // comma-separated list, e.g. "http/1.1" or empty for none (h2 is rejected: HTTP/2 is disabled for Worker connections)

	// DNS over HTTPS (DoH) configuration
	DoHEnabled  bool   `json:"dohEnabled"`  // enable encrypted DNS
	DoHProvider string `json:"dohProvider"` // DoH provider URL
}

// runtimeConfig holds the active DPI evasion and transport configuration
type runtimeConfig struct {
	enableHedging            bool
	enableConnectionRotation bool
	enableFragmentation      bool
	hedgeDelayMs             int
	connectionMaxAgeSec      int
	fragmentDelayMs          int
	fragmentPieces           int
	fragmentSizeMin          int
	fragmentSizeMax          int
	enableRetry              bool
	maxRetryAttempts         int
	retryStrategy            string
	initialBackoffMs         int
	maxBackoffMs             int
	backoffMultiplier        float64
	retryOnTimeout           bool
	enableConnectionPool     bool
	enableConnectionReuse    bool
	maxIdleConns             int
	maxIdleConnsPerHost      int
	idleConnTimeoutSec       int
	cdnEdgeIP                string
	dialTimeoutMs            int
	tlsHandshakeTimeoutMs    int
	responseHeaderTimeoutMs  int
	requestTimeoutMs         int
	alpnProtocols            []string
}

func parseWorkerURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", errors.New("use an https:// Gateway Worker URL without query or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" && parsed.Path != workerRelayPath {
		return "", fmt.Errorf("Worker URL path must be empty or %s", workerRelayPath)
	}
	parsed.Path = workerRelayPath
	return parsed.String(), nil
}

// medovpnFallbackWorkerURLsEnv is the environment variable sendRelayPayload's
// per-attempt endpoint rotation reads from. Set it to a comma-separated list
// of additional Gateway Worker URLs -- each one worker-decoy.js deployed
// unmodified behind a *different* Cloudflare custom domain (or workers.dev
// subdomain) -- and a retry after a transient failure will try the next
// endpoint in the list instead of hammering the same (possibly
// specifically-targeted) domain three times in a row. This is deliberately
// not a settings-file/UI field: it's meant for people who already run more
// than one Worker deployment and know the URLs, not something to prompt an
// average user for.
const medovpnFallbackWorkerURLsEnv = "MEDOVPN_FALLBACK_WORKER_URLS"

// loadFallbackWorkerEndpoints reads and validates medovpnFallbackWorkerURLsEnv.
// Invalid entries are skipped (logged, not fatal) rather than refusing to
// start -- a typo in an optional fallback list shouldn't take down the whole
// app. primary is excluded from the result if it's repeated in the list.
func loadFallbackWorkerEndpoints(primary string) []string {
	raw := os.Getenv(medovpnFallbackWorkerURLsEnv)
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := map[string]struct{}{primary: {}}
	var out []string
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		candidate := strings.TrimSpace(field)
		if candidate == "" {
			continue
		}
		endpoint, err := parseWorkerURL(candidate)
		if err != nil {
			log.Printf("%s: skipping invalid fallback Worker URL %s: %v", medovpnFallbackWorkerURLsEnv, logURL(candidate), err)
			continue
		}
		if _, dup := seen[endpoint]; dup {
			continue
		}
		seen[endpoint] = struct{}{}
		out = append(out, endpoint)
	}
	return out
}

func validateLoopbackAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid loopback address: %w", err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("address must be loopback, such as %s", defaultListenAddress)
	}
	return nil
}

func loadSavedSettings(path string, defaults *proxySettings) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var saved proxySettings
	if err := json.Unmarshal(data, &saved); err != nil {
		log.Printf("saved settings ignored: %v", err)
		return
	}
	// Files written before the version field existed carry DPIConfigured instead.
	if saved.SettingsVersion == 0 && saved.DPIConfigured {
		saved.SettingsVersion = settingsVersion
	}
	// Restore all fields that were explicitly saved
	if saved.WorkerURL != "" {
		defaults.WorkerURL = saved.WorkerURL
	}
	if saved.ListenAddress != "" {
		defaults.ListenAddress = saved.ListenAddress
	}
	if saved.CACertPath != "" {
		defaults.CACertPath = saved.CACertPath
	}
	if saved.CAKeyPath != "" {
		defaults.CAKeyPath = saved.CAKeyPath
	}
	if saved.WorkerCACertPath != "" {
		defaults.WorkerCACertPath = saved.WorkerCACertPath
	}
	if saved.CloudflareAccountID != "" {
		defaults.CloudflareAccountID = saved.CloudflareAccountID
	}
	if saved.CloudflareWorker != "" {
		defaults.CloudflareWorker = saved.CloudflareWorker
	}
	if saved.CloudflareFetchWorker != "" {
		defaults.CloudflareFetchWorker = saved.CloudflareFetchWorker
	}

	// Restore DPI evasion settings
	if saved.SettingsVersion >= settingsVersion {
		defaults.SettingsVersion = saved.SettingsVersion
		defaults.EnableHedging = saved.EnableHedging
		defaults.EnableConnectionRotation = saved.EnableConnectionRotation
		defaults.EnableFragmentation = saved.EnableFragmentation
		defaults.HedgeDelayMs = saved.HedgeDelayMs
		defaults.ConnectionMaxAgeSec = saved.ConnectionMaxAgeSec
		defaults.FragmentDelayMs = saved.FragmentDelayMs
		defaults.FragmentPieces = saved.FragmentPieces
		defaults.FragmentSizeMin = saved.FragmentSizeMin
		defaults.FragmentSizeMax = saved.FragmentSizeMax
	}

	// Restore retry settings - always restore if user has configured DPI
	if saved.SettingsVersion >= settingsVersion {
		defaults.EnableRetry = saved.EnableRetry
		defaults.MaxRetryAttempts = saved.MaxRetryAttempts
		defaults.RetryStrategy = saved.RetryStrategy
		defaults.InitialBackoffMs = saved.InitialBackoffMs
		defaults.MaxBackoffMs = saved.MaxBackoffMs
		defaults.BackoffMultiplier = saved.BackoffMultiplier
		defaults.RetryOnTimeout = saved.RetryOnTimeout
	}

	// Restore connection pool settings - always restore if user has configured DPI
	if saved.SettingsVersion >= settingsVersion {
		defaults.EnableConnectionPool = saved.EnableConnectionPool
		defaults.EnableConnectionReuse = saved.EnableConnectionReuse
		defaults.MaxConcurrentRequests = saved.MaxConcurrentRequests
		defaults.MaxIdleConns = saved.MaxIdleConns
		defaults.MaxIdleConnsPerHost = saved.MaxIdleConnsPerHost
		defaults.IdleConnTimeoutSec = saved.IdleConnTimeoutSec
	}

	// Restore health check settings
	if saved.SettingsVersion >= settingsVersion {
		defaults.EnableHealthCheck = saved.EnableHealthCheck
	}
	if saved.HealthCheckMode != "" {
		defaults.HealthCheckMode = saved.HealthCheckMode
		defaults.HealthCheckInterval = saved.HealthCheckInterval
		defaults.HealthCheckTimeout = saved.HealthCheckTimeout
	}

	// Restore CDN edge IP override
	if saved.CDNEdgeIP != "" {
		defaults.CDNEdgeIP = saved.CDNEdgeIP
	}

	// Restore timeout settings - always restore if user has configured DPI
	if saved.SettingsVersion >= settingsVersion {
		defaults.DialTimeoutMs = saved.DialTimeoutMs
		defaults.TLSHandshakeTimeoutMs = saved.TLSHandshakeTimeoutMs
		defaults.ResponseHeaderTimeoutMs = saved.ResponseHeaderTimeoutMs
		defaults.RequestTimeoutMs = saved.RequestTimeoutMs
	}

	// Restore ALPN settings
	if saved.ALPNProtocols != "" {
		defaults.ALPNProtocols = saved.ALPNProtocols
	}

	// Restore DoH settings
	if saved.DoHEnabled {
		defaults.DoHEnabled = saved.DoHEnabled
		defaults.DoHProvider = saved.DoHProvider
	}
}

// saveSettingsMu serializes all settings saves so concurrent calls (the
// auto-save toggles, the Start handler, and the cloudflare-logs/start
// handler) never produce a torn file.
var saveSettingsMu sync.Mutex

func saveSettings(path string, settings proxySettings) error {
	saveSettingsMu.Lock()
	defer saveSettingsMu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	// Write atomically: write to a temp file in the same directory, then
	// rename over the target so a crash mid-write never corrupts the file.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".settings-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_, writeErr := tmp.Write(data)
	closeErr := tmp.Close()
	if writeErr != nil {
		_ = os.Remove(tmpName)
		return writeErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpName)
		return closeErr
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpName, 0600); err != nil {
			_ = os.Remove(tmpName)
			return err
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func settingsFilePath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "MedoVPN", "settings.json"), nil
}

func gatewayKeyFilePath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "MedoVPN", "gateway_password"), nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// applyConfigDefaults fills in missing configuration values with sensible defaults.
// settingsVersion is stamped into every settings object that the user has
// seen, saved or loaded. Objects with an older or missing version are first
// runs, so the default features are enabled for them.
const settingsVersion = 1

// defaultDoHProvider is used when DoH is enabled without a provider. It is a
// neutral resolver that does not filter content.
const defaultDoHProvider = "https://1.1.1.1/dns-query"

// normalizeSettings trims incidental leading/trailing whitespace from the
// string fields a user is likely to paste into (IPs, provider URLs, protocol
// lists, Cloudflare identifiers, the Worker URL and local paths). It does not
// touch WorkerURL/ListenAddress/CACertPath/CAKeyPath/WorkerCACertPath, which
// the /api/start handler already trims itself.
func normalizeSettings(s *proxySettings) {
	s.CDNEdgeIP = strings.TrimSpace(s.CDNEdgeIP)
	s.DoHProvider = strings.TrimSpace(s.DoHProvider)
	s.ALPNProtocols = strings.TrimSpace(s.ALPNProtocols)
	s.CloudflareAccountID = strings.TrimSpace(s.CloudflareAccountID)
	s.CloudflareWorker = strings.TrimSpace(s.CloudflareWorker)
	s.CloudflareFetchWorker = strings.TrimSpace(s.CloudflareFetchWorker)
	s.WorkerURL = strings.TrimSpace(s.WorkerURL)
	s.ListenAddress = strings.TrimSpace(s.ListenAddress)
	s.CACertPath = strings.TrimSpace(s.CACertPath)
	s.CAKeyPath = strings.TrimSpace(s.CAKeyPath)
	s.WorkerCACertPath = strings.TrimSpace(s.WorkerCACertPath)
}

func applyConfigDefaults(s *proxySettings) {
	if s.DoHProvider == "" {
		s.DoHProvider = defaultDoHProvider
	}
	// First run is decided by the settings version alone, before it is stamped.
	firstRun := s.SettingsVersion < settingsVersion

	// First run: enable the default features unless the user already turned
	// them all off. Once settings are versioned, the user's choices are kept as-is.
	if firstRun {
		if !s.EnableHedging && !s.EnableConnectionRotation && !s.EnableFragmentation {
			// First run - enable all by default
			s.EnableHedging = true
			s.EnableConnectionRotation = true
			s.EnableFragmentation = true
		}
	}

	// Hedging defaults
	if s.HedgeDelayMs == 0 {
		s.HedgeDelayMs = 8000 // 8 seconds: the Worker buffers whole responses, so hedging earlier mostly duplicates work
	}

	// Connection rotation defaults
	if s.ConnectionMaxAgeSec == 0 {
		s.ConnectionMaxAgeSec = 12 // 12 seconds (v3 default)
	}

	// Fragmentation defaults
	// Only apply defaults if user hasn't explicitly configured DPI (firstRun = true is old config)
	if firstRun {
		if s.FragmentDelayMs == 0 {
			s.FragmentDelayMs = 12 // milliseconds - only as first-run default
		}
		if s.FragmentPieces == 0 {
			s.FragmentPieces = 3 // 2-4 in v3, 3 is middle
		}
		if s.FragmentSizeMin == 0 {
			s.FragmentSizeMin = 8 // minimum piece size
		}
		if s.FragmentSizeMax == 0 {
			s.FragmentSizeMax = 120 // reasonable max
		}
	}

	// Retry defaults
	if firstRun {
		// First run - apply v3 defaults for retry
		if s.MaxRetryAttempts == 0 {
			s.MaxRetryAttempts = 3 // v3 default
		}
		if s.RetryStrategy == "" {
			s.RetryStrategy = "exponential"
		}
		if s.InitialBackoffMs == 0 {
			s.InitialBackoffMs = 150 // v3 default
		}
		if s.MaxBackoffMs == 0 {
			s.MaxBackoffMs = 5000
		}
		if s.BackoffMultiplier == 0 {
			s.BackoffMultiplier = 2.0
		}
		s.EnableRetry = true // default to enabled only on first run
	} else {
		// User has configured settings; fill in missing fields only
		if s.RetryStrategy == "" {
			s.RetryStrategy = "exponential"
		}
		if s.BackoffMultiplier == 0 {
			s.BackoffMultiplier = 2.0
		}
	}

	// Connection pool defaults
	if firstRun {
		s.EnableConnectionPool = true  // enabled by default on first run
		s.EnableConnectionReuse = true // keep-alive on by default; without this
		// DisableKeepAlives=true and the 100/20/30 defaults never apply.
	}
	// Default to 20 concurrent relay requests to cap per-process memory.
	// Each in-flight relay holds the JSON payload (~encoded request) plus the
	// full Worker JSON response body before decoding, so a single 32 MiB
	// response can consume ~100-150 MiB of heap. 0 means unlimited; set a
	// sensible default on first run so a burst of large downloads does not
	// exhaust memory.
	// NOTE: maxResponseBody (32 MiB) is a hard cap on the decoded origin body.
	// Responses larger than 32 MiB cannot be proxied and will be rejected with
	// an error. This is an inherent constraint of the JSON-envelope protocol.
	if firstRun && s.MaxConcurrentRequests == 0 {
		s.MaxConcurrentRequests = 40
	}
	if !s.EnableConnectionReuse {
		// Connection reuse disabled: set pool size to 0 (disables keep-alive)
		s.MaxIdleConns = 0
		s.MaxIdleConnsPerHost = 0
		s.IdleConnTimeoutSec = 0
	} else {
		// Connection reuse enabled: apply defaults for pool size if not specified
		if s.MaxIdleConns == 0 {
			s.MaxIdleConns = 100 // v3 default
		}
		if s.MaxIdleConnsPerHost == 0 {
			s.MaxIdleConnsPerHost = 20 // v3 default
		}
		if s.IdleConnTimeoutSec == 0 {
			s.IdleConnTimeoutSec = 10 // short, so dead idle connections are dropped before reuse
		}
	}

	// Health check defaults
	if firstRun {
		s.EnableHealthCheck = false // disabled by default on first run (health checks are optional)
	}
	if s.HealthCheckMode == "" {
		s.HealthCheckMode = "endpoint" // /health endpoint check
	}
	if s.HealthCheckInterval == 0 {
		// Default to 60 s so the value satisfies the form's min="10" constraint
		// and the browser does not silently block the submit on first run.
		s.HealthCheckInterval = 60
	}
	if s.HealthCheckTimeout == 0 {
		s.HealthCheckTimeout = 10 // 10 seconds
	}

	// CDN edge IP is optional - empty by default

	// Timeout defaults
	if s.DialTimeoutMs == 0 {
		s.DialTimeoutMs = 15000 // 15 seconds
	}
	if s.TLSHandshakeTimeoutMs == 0 {
		s.TLSHandshakeTimeoutMs = 15000 // 15 seconds
	}
	if s.ResponseHeaderTimeoutMs == 0 {
		s.ResponseHeaderTimeoutMs = 90000 // 90 seconds: the Worker buffers the whole origin response before sending headers
	}
	if s.RequestTimeoutMs == 0 {
		s.RequestTimeoutMs = 90000 // 90 seconds (v3 default)
	}

	// ALPN defaults: empty by default (let Go choose)
	// User can set to specific protocols like "http/1.1" (h2 is rejected: HTTP/2 is disabled for Worker connections)

	// Mark the settings as current only after the first-run defaults are applied.
	s.SettingsVersion = settingsVersion
}

// settingsToRuntimeConfig converts proxySettings into the runtime configuration
// used by proxyApp during operation.
func settingsToRuntimeConfig(s proxySettings) runtimeConfig {
	return runtimeConfig{
		enableHedging:            s.EnableHedging,
		enableConnectionRotation: s.EnableConnectionRotation,
		enableFragmentation:      s.EnableFragmentation,
		hedgeDelayMs:             s.HedgeDelayMs,
		connectionMaxAgeSec:      s.ConnectionMaxAgeSec,
		fragmentDelayMs:          s.FragmentDelayMs,
		fragmentPieces:           s.FragmentPieces,
		fragmentSizeMin:          s.FragmentSizeMin,
		fragmentSizeMax:          s.FragmentSizeMax,
		enableRetry:              s.EnableRetry,
		maxRetryAttempts:         s.MaxRetryAttempts,
		retryStrategy:            s.RetryStrategy,
		initialBackoffMs:         s.InitialBackoffMs,
		maxBackoffMs:             s.MaxBackoffMs,
		backoffMultiplier:        s.BackoffMultiplier,
		retryOnTimeout:           s.RetryOnTimeout,
		enableConnectionPool:     s.EnableConnectionPool,
		enableConnectionReuse:    s.EnableConnectionReuse,
		maxIdleConns:             s.MaxIdleConns,
		maxIdleConnsPerHost:      s.MaxIdleConnsPerHost,
		idleConnTimeoutSec:       s.IdleConnTimeoutSec,
		cdnEdgeIP:                strings.TrimSpace(s.CDNEdgeIP),
		dialTimeoutMs:            s.DialTimeoutMs,
		tlsHandshakeTimeoutMs:    s.TLSHandshakeTimeoutMs,
		responseHeaderTimeoutMs:  s.ResponseHeaderTimeoutMs,
		requestTimeoutMs:         s.RequestTimeoutMs,
		alpnProtocols:            parseALPNProtocols(s.ALPNProtocols),
	}
}

// parseALPNProtocols converts comma-separated ALPN string to slice, filtering out h2
// since HTTP/2 is disabled for Worker connections by design (to prevent DPI multiplexing)
func parseALPNProtocols(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var protocols []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		// Skip h2/h2c since HTTP/2 is explicitly disabled for this transport
		if p != "" && p != "h2" && p != "h2c" {
			protocols = append(protocols, p)
		}
	}
	return protocols
}

// validateStartSettings checks the settings before the proxy starts. /api/start
// and /api/save-config both call it, so a configuration cannot be saved that
// Start would later refuse for a syntax reason. It does not touch the disk:
// CA certificate and key files are only loaded by Start.
func validateStartSettings(settings proxySettings) error {
	if _, err := parseWorkerURL(settings.WorkerURL); err != nil {
		return err
	}
	if err := validateLoopbackAddress(strings.TrimSpace(settings.ListenAddress)); err != nil {
		return err
	}
	// Validate numeric fields to prevent invalid durations
	// Only validate fields for enabled features

	// DPI Evasion & Transport Configuration validation
	if settings.EnableHedging {
		if settings.HedgeDelayMs <= 0 {
			return errors.New("Hedge Delay must be > 0 ms when hedging is enabled")
		}
	}

	if settings.EnableConnectionRotation {
		if settings.ConnectionMaxAgeSec <= 0 {
			return errors.New("Connection Max Age must be > 0 seconds when connection rotation is enabled")
		}
	}

	if settings.EnableFragmentation {
		if settings.FragmentPieces < 2 || settings.FragmentPieces > 6 {
			return errors.New("Fragment Pieces must be 2-6 when fragmentation is enabled")
		}
		if settings.FragmentSizeMin < 8 {
			return errors.New("Fragment Size Min must be >= 8 bytes when fragmentation is enabled")
		}
		if settings.FragmentSizeMax < settings.FragmentSizeMin {
			return errors.New("Fragment Size Max must be >= Fragment Size Min when fragmentation is enabled")
		}
	}

	if settings.EnableRetry {
		if settings.MaxRetryAttempts < 1 || settings.MaxRetryAttempts > 10 {
			return errors.New("Max Retry Attempts must be 1-10 when retry is enabled")
		}
		if settings.InitialBackoffMs < 0 {
			return errors.New("Initial Backoff must be >= 0 ms when retry is enabled")
		}
		if settings.MaxBackoffMs < 100 {
			return errors.New("Max Backoff must be >= 100 ms when retry is enabled")
		}
		if settings.BackoffMultiplier < 1.0 {
			return errors.New("Backoff Multiplier must be >= 1.0 when retry is enabled")
		}
	}

	// Connection Pool & Concurrency validation (gated on EnableConnectionPool)
	if settings.EnableConnectionPool {
		if settings.MaxConcurrentRequests < 0 {
			return errors.New("Max Concurrent Requests must be >= 0 when connection pool is enabled")
		}

		if settings.EnableConnectionReuse {
			if settings.MaxIdleConns < 0 {
				return errors.New("Max Idle Connections must be >= 0 when connection reuse is enabled")
			}
			if settings.MaxIdleConnsPerHost < 0 {
				return errors.New("Max Idle Connections Per Host must be >= 0 when connection reuse is enabled")
			}
			if settings.IdleConnTimeoutSec < 0 {
				return errors.New("Idle Connection Timeout must be >= 0 seconds when connection reuse is enabled")
			}
		}
	}

	// Health check validation (gated on EnableHealthCheck)
	if settings.EnableHealthCheck {
		if settings.HealthCheckMode == "" {
			return errors.New("Health Check Mode must be set when health check is enabled")
		}
		if settings.HealthCheckInterval < 0 {
			return errors.New("Health Check Interval must be >= 0 seconds when health check is enabled")
		}
		if settings.HealthCheckTimeout <= 0 {
			return errors.New("Health Check Timeout must be > 0 seconds when health check is enabled")
		}
	}

	// Timeout validation (always validate these as they're fundamental)
	if settings.DialTimeoutMs <= 0 {
		return errors.New("Dial Timeout must be > 0 ms")
	}
	if settings.TLSHandshakeTimeoutMs <= 0 {
		return errors.New("TLS Handshake Timeout must be > 0 ms")
	}
	if settings.ResponseHeaderTimeoutMs <= 0 {
		return errors.New("Response Header Timeout must be > 0 ms")
	}
	if settings.RequestTimeoutMs <= 0 {
		return errors.New("Request Timeout must be > 0 ms")
	}

	// CDN edge IP validation
	if settings.CDNEdgeIP != "" {
		if net.ParseIP(settings.CDNEdgeIP) == nil {
			return errors.New("CDN Edge IP must be a valid IP address")
		}
	}

	// DoH provider validation
	if settings.DoHEnabled {
		if settings.DoHProvider == "" {
			return errors.New("DoH Provider URL is required when DoH is enabled")
		}
		// Validate that provider is a proper URL
		if !strings.HasPrefix(strings.ToLower(settings.DoHProvider), "https://") {
			return errors.New("DoH Provider must be an HTTPS URL (https://...)")
		}
		// Try to parse it as a URL
		if _, err := url.Parse(settings.DoHProvider); err != nil {
			return errors.New("DoH Provider must be a valid HTTPS URL")
		}
	}

	// Validate ALPN protocols - reject h2 since HTTP/2 is disabled for Worker connections
	if settings.ALPNProtocols != "" {
		for _, proto := range strings.Split(settings.ALPNProtocols, ",") {
			proto = strings.TrimSpace(proto)
			if proto == "h2" || proto == "h2c" {
				return errors.New("HTTP/2 (h2/h2c) is disabled for Worker connections by design. Use http/1.1 or leave empty.")
			}
		}
	}
	return nil
}

const (
	defaultListenAddress  = "127.0.0.1:2020"
	defaultGUIAddress     = "127.0.0.1:2021"
	defaultWorkerURL      = "https://your-worker.example.com"
	workerRelayPath       = "/relay"
	maxRequestBody        = 10 << 20
	maxResponseBody       = 32 << 20
	maxRelayJSON          = 48 << 20
	maxWorkerCACertSize   = 1 << 20
	tlsRequestReadTimeout = 90 * time.Second

	// workerConnMaxAgeJitter is added (0..jitter, re-rolled per connection) to
	// the configured connection max age, so rotations don't happen on a
	// perfectly constant cadence.
	workerConnMaxAgeJitter = 4 * time.Second

	// Winsock error codes. Go's windows syscall package defines WSAECONNRESET and
	// WSAECONNABORTED, but not the refused and timed-out codes, so they are
	// named here by their documented values.
	wsaeConnRefused = syscall.Errno(10061) // WSAECONNREFUSED
	wsaeTimedOut    = syscall.Errno(10060) // WSAETIMEDOUT

	// maxRequestHeaderBytes caps the header section of one browser request on the
	// local TLS proxy. 64 KiB is far above real cookie-heavy headers.
	maxRequestHeaderBytes = 64 << 10

	// Retry and hedge budget (see retryBudget). Each logical request deposits
	// retryBudgetRatio tokens; each retry or hedge spends one whole token.
	retryBudgetRatio   = 0.5
	retryBudgetMax     = 50.0
	retryBudgetInitial = 20.0

	// workerErrorSnippetBytes bounds how much of a Worker error body is kept
	// for logs and browser-facing error text.
	workerErrorSnippetBytes = 512

	// relayPaddingMaxBytes bounds the random padding buildRelayPayload adds
	// to each Worker request so its on-wire size isn't a near-constant
	// function of the wrapped request. The Worker never reads this field
	// (see "p" below and worker-decoy.js), so it's pure padding.
	relayPaddingMaxBytes = 512
)

// dpapiMagic marks a secret file that holds DPAPI-protected data. Files without
// it are legacy plaintext. They are read as they are and rewritten protected
// the next time they are saved.
const dpapiMagic = "MEDOVPN-DPAPI-1\n"

// dataBlob matches the Windows DATA_BLOB structure.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// dpapiTransform runs CryptProtectData or CryptUnprotectData on input. Both
// take the same arguments and return a buffer that Windows allocated.
func dpapiTransform(proc *syscall.LazyProc, input []byte) ([]byte, error) {
	var in dataBlob
	if len(input) > 0 {
		in = dataBlob{cbData: uint32(len(input)), pbData: &input[0]}
	}
	var out dataBlob
	ok, _, callErr := proc.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // description
		0, // optional entropy
		0, // reserved
		0, // prompt struct
		0, // flags
		uintptr(unsafe.Pointer(&out)),
	)
	if ok == 0 {
		return nil, fmt.Errorf("Windows DPAPI call failed: %w", callErr)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	result := make([]byte, out.cbData)
	if out.cbData > 0 {
		copy(result, unsafe.Slice(out.pbData, out.cbData))
	}
	return result, nil
}

// protectSecret encrypts plain with DPAPI, so that only this Windows user
// account can decrypt it. It returns the text to store in the secret file.
func protectSecret(plain []byte) ([]byte, error) {
	sealed, err := dpapiTransform(procCryptProtectData, plain)
	if err != nil {
		return nil, err
	}
	return []byte(dpapiMagic + base64.StdEncoding.EncodeToString(sealed) + "\n"), nil
}

// unprotectSecret reverses protectSecret. Data without the magic prefix is
// legacy plaintext and is returned unchanged.
func unprotectSecret(data []byte) ([]byte, error) {
	if !bytes.HasPrefix(data, []byte(dpapiMagic)) {
		return data, nil
	}
	sealed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data[len(dpapiMagic):])))
	if err != nil {
		return nil, fmt.Errorf("decode protected secret: %w", err)
	}
	return dpapiTransform(procCryptUnprotectData, sealed)
}

func loadGatewayKey(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	plain, err := unprotectSecret(data)
	if err != nil {
		log.Printf("saved Gateway password could not be read: %v", err)
		return ""
	}
	return strings.TrimSpace(string(plain))
}

// writeSecretFileAtomic writes data to a temp file in the same directory and
// renames it over path, so a crash mid-write never leaves a torn secret file.
func writeSecretFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".secret-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_, writeErr := tmp.Write(data)
	closeErr := tmp.Close()
	if writeErr != nil {
		_ = os.Remove(tmpName)
		return writeErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpName)
		return closeErr
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpName, 0600); err != nil {
			_ = os.Remove(tmpName)
			return err
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func saveGatewayKey(path, key string) error {
	if key == "" {
		return errors.New("Worker password is empty")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(directory, 0700); err != nil {
			return err
		}
	}
	sealed, err := protectSecret([]byte(key))
	if err != nil {
		return err
	}
	return writeSecretFileAtomic(path, sealed)
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func loadCloudflareToken(path string) string {
	if token := strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN")); token != "" {
		return token
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	plain, err := unprotectSecret(data)
	if err != nil {
		log.Printf("saved Cloudflare token could not be read: %v", err)
		return ""
	}
	return strings.TrimSpace(string(plain))
}

func saveCloudflareToken(path, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("Cloudflare API token is empty")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(directory, 0700); err != nil {
			return err
		}
	}
	sealed, err := protectSecret([]byte(token))
	if err != nil {
		return err
	}
	return writeSecretFileAtomic(path, sealed)
}

func cloudflareTokenFilePath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "MedoVPN", "cloudflare_api_token"), nil
}

var (
	dllCrypt32             = syscall.NewLazyDLL("crypt32.dll")
	procCryptProtectData   = dllCrypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = dllCrypt32.NewProc("CryptUnprotectData")
	dllKernel32            = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree          = dllKernel32.NewProc("LocalFree")
)

// maxCachedLeaves bounds the per-host certificate cache. Clearing it costs a
// few extra key generations, so the cache is simply reset when it fills.
const maxCachedLeaves = 4096

type localCA struct {
	certificate  *x509.Certificate
	privateKey   crypto.Signer
	certPath     string
	certificates sync.Map
	cachedLeaves int64 // approximate count of entries in certificates
}

type idleReadDeadlineConn struct {
	net.Conn
	timeout   time.Duration
	interrupt atomic.Bool
}

func (c *idleReadDeadlineConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	// interruptRead may have run between the two steps above, which would
	// overwrite its deadline with the one just set. Re-arm it in that case.
	if c.interrupt.Load() {
		_ = c.Conn.SetReadDeadline(time.Now())
	}
	return c.Conn.Read(p)
}

// interruptRead makes a blocked or future Read fail with a timeout at once,
// without closing the connection.
func (c *idleReadDeadlineConn) interruptRead() {
	c.interrupt.Store(true)
	_ = c.Conn.SetReadDeadline(time.Now())
}

func (c *idleReadDeadlineConn) interrupted() bool {
	return c.interrupt.Load()
}

// resume ends an interruption so that reads behave normally again.
func (c *idleReadDeadlineConn) resume() {
	c.interrupt.Store(false)
	_ = c.Conn.SetReadDeadline(time.Time{})
}

func (p *proxyApp) handleConnect(w http.ResponseWriter, r *http.Request) {
	connectHost, err := hostFromAuthority(r.Host)
	if err != nil {
		http.Error(w, "invalid CONNECT host", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "HTTP connection hijacking is unavailable", http.StatusInternalServerError)
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	if !p.trackConnection(conn) {
		_ = conn.Close()
		return
	}
	defer p.untrackConnection(conn)
	defer conn.Close()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}

	tlsConn := tls.Server(&bufferedConn{Conn: conn, reader: buffered.Reader}, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hello.ServerName
			if host == "" {
				host = connectHost
			}
			return p.ca.certificateFor(host)
		},
	})
	_ = tlsConn.SetDeadline(time.Now().Add(20 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		// Most often the browser does not trust the Gateway CA. From here that
		// looks identical to any other failed handshake, so say so explicitly.
		log.Printf("TLS handshake with the browser for %s failed: %v (if this happens for every HTTPS site, the browser does not trust the Gateway CA)", connectHost, err)
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	requestHost := tlsConn.ConnectionState().ServerName
	if requestHost == "" {
		requestHost = connectHost
	}
	// The Host header is the normal source of the destination. When it is
	// missing, fall back to the CONNECT authority, keeping its port if it is
	// not the HTTPS default.
	fallbackAuthority := requestHost
	if _, port, splitErr := net.SplitHostPort(strings.TrimSpace(r.Host)); splitErr == nil && port != "" && port != "443" {
		fallbackAuthority = net.JoinHostPort(requestHost, port)
	}
	p.serveTLSRequests(tlsConn, fallbackAuthority)
}

// serveTLSRequests answers HTTP/1.1 requests on one decrypted CONNECT tunnel.
//
// One buffered reader serves the whole connection. Headers and bodies are both
// read through it, so bytes read ahead for one request are never lost to the
// next one. A request body is fully consumed before the next request is parsed,
// and any part the relay did not read (for example on a GET) is drained first.
func (p *proxyApp) serveTLSRequests(conn net.Conn, connectHost string) {
	idle := &idleReadDeadlineConn{Conn: conn, timeout: tlsRequestReadTimeout}
	budget := &headerBudgetReader{r: idle}
	reader := bufio.NewReaderSize(budget, 32<<10)

	for {
		budget.arm(maxRequestHeaderBytes)
		request, err := http.ReadRequest(reader)
		budget.disarm()
		if err != nil {
			switch {
			case budget.tripped:
				log.Printf("HTTPS request to %s has headers larger than %d KiB; closing the connection", connectHost, maxRequestHeaderBytes>>10)
				writeSimpleResponse(conn, http.StatusRequestHeaderFieldsTooLarge, "request headers too large")
			case isQuietReadError(err):
				// The client closed a keep-alive connection, or it sat idle past the timeout.
			default:
				log.Printf("HTTPS request to %s could not be read: %v", connectHost, err)
			}
			return
		}

		if isUpgradeRequest(request.Header) {
			writeSimpleResponse(conn, http.StatusNotImplemented, "WebSocket upgrades are not supported by the Worker fetch relay")
			closeRequestBody(request)
			return
		}
		if strings.EqualFold(strings.TrimSpace(request.Header.Get("Expect")), "100-continue") {
			if _, err := io.WriteString(conn, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
				closeRequestBody(request)
				return
			}
			request.Header.Del("Expect")
		}

		target, err := targetForTLSRequest(request, connectHost)
		if err != nil {
			writeSimpleResponse(conn, http.StatusBadRequest, "invalid HTTPS request target")
			closeRequestBody(request)
			return
		}

		if err := bufferRequestBody(request); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, errRequestBodyTooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			writeSimpleResponse(conn, status, err.Error())
			return
		}

		// Watch the browser's side of the tunnel while the Worker call runs. If
		// the browser closes the connection, cancel the call rather than letting
		// it finish for nobody. The body is already in memory, so this goroutine
		// is the only reader of the connection while the relay is in flight.
		ctx, cancel := context.WithCancel(p.ctx)
		watchDone := make(chan struct{})
		go func() {
			defer close(watchDone)
			if _, err := reader.Peek(1); err != nil && !idle.interrupted() && !isTimeoutError(err) {
				cancel()
			}
		}()
		response, relayErr := p.relayWithHedge(ctx, request, target)
		idle.interruptRead()
		<-watchDone
		idle.resume()
		if relayErr != nil {
			if errors.Is(relayErr, context.Canceled) {
				// The browser went away (or the proxy is stopping): nobody is
				// waiting for an answer, so this is neither logged nor a 502.
				cancel()
				closeRequestBody(request)
				return
			}
			log.Printf("HTTPS relay failed for %s: %v", logURL(target), relayErr)
			cancel()
			closeRequestBody(request)
			status, message := relayErrorResponse(relayErr)
			writeSimpleResponse(conn, status, message)
			return
		}
		response.Close = response.Close || request.Close

		writeErr := response.Write(&writeIdleConn{Conn: conn, timeout: 30 * time.Second})
		_ = conn.SetWriteDeadline(time.Time{})
		_ = response.Body.Close()
		cancel()

		drainErr := drainRequestBody(request)
		if writeErr != nil || drainErr != nil || response.Close {
			return
		}
	}
}

// writeIdleConn arms a fresh write deadline before every write, so a large
// response that the browser drains slowly is only cut off when the browser
// stops reading for a whole timeout, not when the total transfer is long.
type writeIdleConn struct {
	net.Conn
	timeout time.Duration
}

func (c *writeIdleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(p)
}

// errHeaderTooLarge is reported when a request's header section exceeds
// maxRequestHeaderBytes. Bodies are never counted against this limit.
var errHeaderTooLarge = errors.New("request headers exceed the size limit")

// headerBudgetReader caps how many bytes http.ReadRequest may pull from the
// socket while it parses a request's headers. Once disarmed it is a plain
// pass-through, so body bytes are never limited by the header budget.
type headerBudgetReader struct {
	r         io.Reader
	armed     bool
	remaining int64
	tripped   bool
}

func (h *headerBudgetReader) arm(limit int64) {
	h.armed = true
	h.remaining = limit
	h.tripped = false
}

func (h *headerBudgetReader) disarm() {
	h.armed = false
}

func (h *headerBudgetReader) Read(p []byte) (int, error) {
	if !h.armed {
		return h.r.Read(p)
	}
	if h.remaining <= 0 {
		h.tripped = true
		return 0, errHeaderTooLarge
	}
	if int64(len(p)) > h.remaining {
		p = p[:h.remaining]
	}
	n, err := h.r.Read(p)
	h.remaining -= int64(n)
	return n, err
}

// isQuietReadError reports read failures that are normal on a keep-alive
// connection: the client hung up, or it went idle past the timeout.
func isQuietReadError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// drainRequestBody reads whatever part of a request body the relay did not
// consume, so the next request on the connection starts at the right byte.
func drainRequestBody(request *http.Request) error {
	if request.Body == nil {
		return nil
	}
	n, err := io.Copy(io.Discard, io.LimitReader(request.Body, maxRequestBody+1))
	_ = request.Body.Close()
	if err != nil {
		return err
	}
	if n > maxRequestBody {
		return errors.New("request body exceeds the 10 MiB limit")
	}
	return nil
}

func defaultCAPaths() (string, string) {
	certPath := strings.TrimSpace(os.Getenv("CA_CERT_FILE"))
	keyPath := strings.TrimSpace(os.Getenv("CA_KEY_FILE"))

	// Use UserConfigDir on all platforms
	if certPath == "" {
		base, err := os.UserConfigDir()
		if err == nil {
			certPath = filepath.Join(base, "MedoVPN", "mycert.crt")
		} else {
			// Fallback to current directory if UserConfigDir fails
			certPath = filepath.Join(".", "mycert.crt")
		}
	}
	if keyPath == "" {
		base, err := os.UserConfigDir()
		if err == nil {
			keyPath = filepath.Join(base, "MedoVPN", "mycert.key")
		} else {
			// Fallback to current directory if UserConfigDir fails
			keyPath = filepath.Join(".", "mycert.key")
		}
	}
	return certPath, keyPath
}

func loadCA(certPath, keyPath string) (*localCA, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate %s: %w", certPath, err)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key %s: %w", keyPath, err)
	}
	certificate, err := x509.ParseCertificate(decodePEMOrDER(certData))
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !certificate.IsCA || (certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageCertSign == 0) {
		return nil, errors.New("certificate is not permitted to sign certificates")
	}
	now := time.Now()
	if certificate.NotBefore.After(now) || !certificate.NotAfter.After(now) {
		return nil, errors.New("CA certificate is not currently valid")
	}
	// Use decodePrivateKeyPEM (not decodePEMOrDER) so that an openssl ecparam
	// -genkey file, which starts with an "EC PARAMETERS" PEM block, is handled
	// correctly by scanning past it to the actual "EC PRIVATE KEY" block.
	privateKey, err := parsePrivateKey(decodePrivateKeyPEM(keyData))
	if err != nil {
		return nil, fmt.Errorf("parse CA private key: %w", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA private key cannot sign certificates")
	}
	certificatePublic, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, err
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(certificatePublic, keyPublic) {
		return nil, errors.New("CA certificate and private key do not match")
	}
	return &localCA{certificate: certificate, privateKey: signer, certPath: certPath}, nil
}

func loadWorkerTLSConfig(certPath string) (*tls.Config, error) {
	certPath = strings.TrimSpace(certPath)
	if certPath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read Worker TLS CA certificate %s: %w", certPath, err)
	}
	certificates, err := parseWorkerCACertificates(data)
	if err != nil {
		return nil, err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system certificate roots: %w", err)
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	for _, certificate := range certificates {
		roots.AddCert(certificate)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, nil
}

func parseWorkerCACertificates(data []byte) ([]*x509.Certificate, error) {
	remaining := data
	certificates := make([]*x509.Certificate, 0, 1)
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			if len(certificates) == 0 {
				certificate, err := x509.ParseCertificate(data)
				if err != nil {
					return nil, fmt.Errorf("parse Worker TLS certificate: %w", err)
				}
				certificates = append(certificates, certificate)
			} else if len(bytes.TrimSpace(remaining)) != 0 {
				return nil, errors.New("Worker TLS certificate bundle has invalid trailing data")
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("upload a CA certificate file without a private key")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse Worker TLS CA certificate: %w", err)
		}
		certificates = append(certificates, certificate)
		remaining = rest
	}
	if len(certificates) == 0 {
		return nil, errors.New("certificate file contains no certificates")
	}
	now := time.Now()
	for _, certificate := range certificates {
		if !certificate.IsCA || (certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageCertSign == 0) {
			return nil, errors.New("Worker TLS certificate must be a CA allowed to sign certificates")
		}
		if certificate.NotBefore.After(now) || !certificate.NotAfter.After(now) {
			return nil, errors.New("Worker TLS CA certificate is not currently valid")
		}
	}
	return certificates, nil
}

func storeWorkerCACertificate(settingsPath string, data []byte) (string, error) {
	if len(data) == 0 || len(data) > maxWorkerCACertSize {
		return "", fmt.Errorf("certificate file must be between 1 byte and %d MiB", maxWorkerCACertSize>>20)
	}
	if _, err := parseWorkerCACertificates(data); err != nil {
		return "", err
	}
	directory := filepath.Dir(settingsPath)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", fmt.Errorf("create certificate storage directory: %w", err)
	}
	path := filepath.Join(directory, "worker-tls-ca.crt")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", fmt.Errorf("save Worker TLS CA certificate: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0600); err != nil {
			return "", fmt.Errorf("protect Worker TLS CA certificate file: %w", err)
		}
	}
	return path, nil
}

func decodePEMOrDER(data []byte) []byte {
	block, _ := pem.Decode(data)
	if block != nil {
		return block.Bytes
	}
	return data
}

// decodePrivateKeyPEM iterates over all PEM blocks in data and returns the
// DER bytes of the first block whose type looks like a private key. This
// handles the common `openssl ecparam -genkey` output format, which writes an
// "EC PARAMETERS" block before the "EC PRIVATE KEY" block; a plain
// pem.Decode would stop at the first (wrong) block and hand us unusable bytes
// .
func decodePrivateKeyPEM(data []byte) []byte {
	privateKeyTypes := map[string]bool{
		"EC PRIVATE KEY":        true,
		"RSA PRIVATE KEY":       true,
		"PRIVATE KEY":           true, // PKCS#8
		"ENCRYPTED PRIVATE KEY": true,
	}
	remaining := data
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if privateKeyTypes[block.Type] {
			return block.Bytes
		}
		remaining = rest
	}
	// No PEM key block found; return raw data (DER fallback).
	return data
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported CA private key format")
}

func (ca *localCA) certificateFor(host string) (*tls.Certificate, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return nil, errors.New("empty certificate host")
	}
	if cached, ok := ca.certificates.Load(host); ok {
		cert := cached.(*tls.Certificate)
		// Regenerate if the leaf is expired or will expire within 24 hours.
		// Without this check the proxy serves expired certificates after ~30
		// days of uptime, causing every HTTPS site to fail with a cert error.
		if cert.Leaf != nil && time.Until(cert.Leaf.NotAfter) > 24*time.Hour {
			return cert, nil
		}
		// Certificate is expired or about to expire; fall through to regenerate.
		if _, loaded := ca.certificates.LoadAndDelete(host); loaded {
			atomic.AddInt64(&ca.cachedLeaves, -1)
		}
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	notBefore := now.Add(-time.Minute)
	if notBefore.Before(ca.certificate.NotBefore) {
		notBefore = ca.certificate.NotBefore
	}
	notAfter := now.AddDate(0, 1, 0)
	if ca.certificate.NotAfter.Before(notAfter) {
		notAfter = ca.certificate.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &leafKey.PublicKey, ca.privateKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certificate := &tls.Certificate{Certificate: [][]byte{der, ca.certificate.Raw}, PrivateKey: leafKey, Leaf: leaf}
	actual, loaded := ca.certificates.LoadOrStore(host, certificate)
	if !loaded && atomic.AddInt64(&ca.cachedLeaves, 1) > maxCachedLeaves {
		// Cache is full: drop every other entry and keep only the new leaf.
		ca.certificates.Range(func(key, _ any) bool {
			if key != host {
				ca.certificates.Delete(key)
			}
			return true
		})
		atomic.StoreInt64(&ca.cachedLeaves, 1)
	}
	return actual.(*tls.Certificate), nil
}

func writeSimpleResponse(w io.Writer, status int, message string) {
	body := []byte(message + "\n")
	response := &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
	}
	response.Header.Set("Content-Type", "text/plain; charset=utf-8")
	_ = response.Write(w)
}

func closeRequestBody(request *http.Request) {
	if request != nil && request.Body != nil {
		_ = request.Body.Close()
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// agedConn wraps a dialed Worker connection and records when it was created,
// so attemptRelay can retire it once it has outlived its age limit.
//
// It deliberately does nothing on the read or write path. The previous version
// probed for closure with a 1 ns read deadline from a side goroutine, which
// raced the transport's own reader and killed live connections. Age is only
// observed here; rotation happens at a safe point, right after a complete
// response has been read (see attemptRelay).
type agedConn struct {
	net.Conn
	createdAt time.Time
	maxAge    time.Duration
	tracker   *connAgeTracker
	closeOnce sync.Once
}

func (c *agedConn) Close() error {
	c.closeOnce.Do(func() { c.tracker.remove(c) })
	return c.Conn.Close()
}

func (c *agedConn) expired(now time.Time) bool {
	return now.Sub(c.createdAt) >= c.maxAge
}

// connAgeTracker holds the set of live agedConns. A nil tracker is valid and
// tracks nothing, so one-off probes can share the same dialer.
type connAgeTracker struct {
	mu   sync.Mutex
	live map[*agedConn]struct{}
}

func newConnAgeTracker() *connAgeTracker {
	return &connAgeTracker{live: make(map[*agedConn]struct{})}
}

func (t *connAgeTracker) add(c *agedConn) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.live[c] = struct{}{}
	t.mu.Unlock()
}

func (t *connAgeTracker) remove(c *agedConn) {
	if t == nil {
		return
	}
	t.mu.Lock()
	delete(t.live, c)
	t.mu.Unlock()
}

// newWorkerTransport builds the single transport used for Worker connections.
// Relay traffic and the health probe both go through it, so the probe exercises
// the same dialing, fragmentation and TLS path as real requests. HTTP/2 stays
// off: multiplexing would put several requests on one connection, so one
// failure would take all of them down.
func newWorkerTransport(config runtimeConfig, tlsConfig *tls.Config, dial func(ctx context.Context, network, address string) (net.Conn, error), tracker *connAgeTracker) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		MaxIdleConns:          config.maxIdleConns,
		MaxIdleConnsPerHost:   config.maxIdleConnsPerHost,
		IdleConnTimeout:       time.Duration(config.idleConnTimeoutSec) * time.Second,
		TLSHandshakeTimeout:   time.Duration(config.tlsHandshakeTimeoutMs) * time.Millisecond,
		ResponseHeaderTimeout: time.Duration(config.responseHeaderTimeoutMs) * time.Millisecond,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		DisableKeepAlives:     !config.enableConnectionReuse,
		TLSClientConfig:       tlsConfig,
		DialContext:           newHardenedDialer(dial, config, tracker),
	}
}

// retryBudget caps the extra Worker requests (retries and hedges) the proxy may
// send relative to real traffic. Each logical request deposits a fraction of a
// token and each retry or hedge withdraws a whole one. During an outage the
// budget runs out and load stops multiplying, instead of one browser request
// turning into six or more Worker calls.
type retryBudget struct {
	mu     sync.Mutex
	tokens float64
}

func newRetryBudget() *retryBudget {
	return &retryBudget{tokens: retryBudgetInitial}
}

func (b *retryBudget) deposit() {
	b.mu.Lock()
	b.tokens += retryBudgetRatio
	if b.tokens > retryBudgetMax {
		b.tokens = retryBudgetMax
	}
	b.mu.Unlock()
}

func (b *retryBudget) withdraw() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// fragmentMinLen is the smallest first-Write size worth fragmenting.
// Go's TLS ClientHello to a Cloudflare-fronted host easily clears this
// (SNI + ALPN + key share + the rest routinely puts it well past 200
// bytes), while something that's already tiny gains nothing from being
// split and would just add latency.
const fragmentMinLen = 64

// fragmentingConn splits only the very first Write on a connection -- which,
// for a TLS client connection, is always the ClientHello -- into 2-6 pieces
// (configurable) at random or configured boundaries, with a configurable
// jittered pause between each. Every later Write passes through untouched.
//
// The point: a lot of DPI boxes, including the simpler ones GFW-adjacent
// deployments still run, grab the SNI by parsing whatever bytes arrive in
// the *first* TCP segment of a new flow, because that's cheap and almost
// always sufficient against an unmodified TLS stack. Splitting the
// ClientHello across several small writes -- combined with Go's net package
// already defaulting new TCP connections to TCP_NODELAY, which this also
// sets explicitly below so each Write tends to go out as its own segment --
// means the SNI isn't sitting whole in that first segment anymore. This is
// exactly the "ClientHello fragmentation" option ArasClient's Aether/core
// integration exposes, applied here without any new dependency.
//
// It is not a fix for the specific failure mode in this project's tail logs
// (a connection that completes its handshake fine and gets killed 12-23s
// *into* an established flow is not being blocked by SNI inspection at
// setup time -- see the connection-age rotation in attemptRelay). It is a second,
// independent layer against a *different* class of DPI: the kind that
// blocks on SNI/handshake inspection before a connection is ever allowed to
// open. Keep it, but don't expect it to touch the mid-flow kill problem.
type fragmentingConn struct {
	net.Conn
	wroteFirst bool
	pieces     int // how many pieces to split into (0 = random 2-4)
	delayMs    int // milliseconds between fragments (0 = random 0-12ms)
	minSize    int // minimum fragment size in bytes
	maxSize    int // maximum fragment size in bytes
}

func newFragmentingConn(c net.Conn, pieces, delayMs, minSize, maxSize int) *fragmentingConn {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	return &fragmentingConn{
		Conn:    c,
		pieces:  pieces,
		delayMs: delayMs,
		minSize: minSize,
		maxSize: maxSize,
	}
}

// sniOffsets locates the hostname bytes of the server_name extension inside a
// raw TLS ClientHello record, so fragmentation can cut across the SNI
// directly instead of guessing at random boundaries. It returns ok=false for
// anything that isn't a recognizable, fully-buffered ClientHello -- including
// one that's simply too short to contain the field it's looking for next --
// rather than risk reading past the end of p.
func sniOffsets(p []byte) (start, end int, ok bool) {
	if len(p) < 43 || p[0] != 0x16 || p[5] != 0x01 {
		return 0, 0, false
	}
	i := 43
	// Session ID: 1-byte length prefix + id.
	if i >= len(p) {
		return 0, 0, false
	}
	i += 1 + int(p[i])
	if i+2 > len(p) {
		return 0, 0, false
	}
	// Cipher suites: 2-byte length prefix + suites.
	i += 2 + (int(p[i])<<8 | int(p[i+1]))
	if i+1 > len(p) {
		return 0, 0, false
	}
	// Compression methods: 1-byte length prefix + methods.
	i += 1 + int(p[i])
	if i+2 > len(p) {
		return 0, 0, false
	}
	// Extensions: 2-byte total length, then (type:2, length:2, body) entries.
	extEnd := i + 2 + (int(p[i])<<8 | int(p[i+1]))
	i += 2
	if extEnd > len(p) {
		return 0, 0, false
	}
	for i+4 <= extEnd {
		extType := int(p[i])<<8 | int(p[i+1])
		extLen := int(p[i+2])<<8 | int(p[i+3])
		body := i + 4
		if body+extLen > extEnd {
			return 0, 0, false
		}
		if extType == 0 && extLen >= 5 {
			// server_name: 2-byte list length, 1-byte name type, 2-byte name
			// length, then the hostname itself.
			if body+9 > len(p) {
				return 0, 0, false
			}
			nameLen := int(p[body+7])<<8 | int(p[body+8])
			start = body + 9
			end = start + nameLen
			if end > len(p) {
				return 0, 0, false
			}
			return start, end, true
		}
		i = body + extLen
	}
	return 0, 0, false
}

func (c *fragmentingConn) Write(p []byte) (int, error) {
	if c.wroteFirst || len(p) < fragmentMinLen {
		c.wroteFirst = true
		return c.Conn.Write(p)
	}
	c.wroteFirst = true

	pieceCount := c.pieces
	if pieceCount == 0 {
		pieceCount = 2 + int(cryptoRandInt63n(3)) // 2..4 pieces (v3 default)
	}

	var pieces [][]byte
	if start, end, ok := sniOffsets(p); ok && end-start >= 2 {
		minSize := c.minSize
		if minSize <= 0 {
			minSize = 8
		}
		cuts := []int{start + (end-start)/2}
		if pieceCount > 2 {
			extra := pieceCount - 2
			lo, hi := minSize, len(p)-minSize
			for attempt := 0; attempt < extra*20 && len(cuts) < 1+extra && hi > lo; attempt++ {
				candidate := lo + int(cryptoRandInt63n(int64(hi-lo+1)))
				distinct := true
				for _, existing := range cuts {
					diff := candidate - existing
					if diff < 0 {
						diff = -diff
					}
					if diff < minSize {
						distinct = false
						break
					}
				}
				if distinct {
					cuts = append(cuts, candidate)
				}
			}
		}
		sort.Ints(cuts)
		pieces = make([][]byte, 0, len(cuts)+1)
		prev := 0
		for _, cut := range cuts {
			if cut <= prev || cut >= len(p) {
				continue
			}
			pieces = append(pieces, p[prev:cut])
			prev = cut
		}
		pieces = append(pieces, p[prev:])
	} else {
		// Fall back to boundary-agnostic splitting when the SNI can't be
		// located (not a ClientHello, no server_name extension, parse
		// failure, and so on).
		pieces = splitPieces(p, pieceCount, c.minSize, c.maxSize)
	}

	total := 0
	for i, piece := range pieces {
		n, err := c.Conn.Write(piece)
		total += n
		if err != nil {
			return total, err
		}
		if i < len(pieces)-1 && c.delayMs > 0 {
			// A delay of 0 means no delay between pieces.
			time.Sleep(time.Duration(c.delayMs) * time.Millisecond)
		}
	}
	return total, nil
}

// splitPieces cuts p into at most `pieces` chunks at random boundaries. Each
// chunk is at least minSize bytes. If maxSize is positive, every chunk except
// the last is at most maxSize bytes; the last chunk takes whatever remains, so
// the number of pieces never exceeds the configured count. If p is too short
// to honour the request, it is returned whole.
func splitPieces(p []byte, pieces, minSize, maxSize int) [][]byte {
	if minSize <= 0 {
		minSize = 8
	}
	if maxSize > 0 && maxSize < minSize {
		maxSize = minSize
	}
	if pieces < 2 || len(p) < pieces*minSize {
		return [][]byte{p}
	}
	out := make([][]byte, 0, pieces)
	remaining := p
	for i := 0; i < pieces-1 && len(remaining) > 0; i++ {
		// Leave at least minSize bytes for each of the pieces still to come.
		reserve := (pieces - 1 - i) * minSize
		maxCut := len(remaining) - reserve
		if maxSize > 0 && maxCut > maxSize {
			maxCut = maxSize
		}
		if maxCut < minSize {
			break
		}
		cut := minSize + int(cryptoRandInt63n(int64(maxCut-minSize+1)))
		out = append(out, remaining[:cut])
		remaining = remaining[cut:]
	}
	if len(remaining) > 0 {
		out = append(out, remaining)
	}
	return out
}

// newHardenedDialer composes fragmentingConn (first-Write ClientHello
// splitting) with agedConn (connection-age rotation), respecting the runtime
// configuration. Features can be individually disabled via config flags.
func newHardenedDialer(base func(ctx context.Context, network, address string) (net.Conn, error), config runtimeConfig, tracker *connAgeTracker) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		// CDN edge IP override
		if config.cdnEdgeIP != "" && network == "tcp" {
			// Override address to use the specified IP while keeping original for SNI/Host
			host, port, err := net.SplitHostPort(address)
			if err == nil && host != "" {
				// Replace host with the edge IP
				address = net.JoinHostPort(config.cdnEdgeIP, port)
			}
		}

		conn, err := base(ctx, network, address)
		if err != nil {
			return nil, err
		}

		// Apply fragmentation if enabled
		if config.enableFragmentation {
			conn = newFragmentingConn(conn, config.fragmentPieces, config.fragmentDelayMs, config.fragmentSizeMin, config.fragmentSizeMax)
		}

		// Apply connection-age tracking if enabled. attemptRelay closes an
		// over-age connection right after it finishes a response.
		if config.enableConnectionRotation && tracker != nil {
			maxAge := time.Duration(config.connectionMaxAgeSec) * time.Second
			effectiveMaxAge := maxAge
			if workerConnMaxAgeJitter > 0 {
				effectiveMaxAge += time.Duration(cryptoRandInt63n(int64(workerConnMaxAgeJitter)))
			}
			ac := &agedConn{Conn: conn, createdAt: time.Now(), maxAge: effectiveMaxAge, tracker: tracker}
			tracker.add(ac)
			conn = ac
		}

		return conn, nil
	}
}

// cryptoRandInt63n returns a uniform random value in [0, n) using the same
// crypto/rand source as the rest of this file (the CA key generation already
// imports it), so no additional math/rand seeding is needed. n must be > 0.
func cryptoRandInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Extremely unlikely (would mean the OS CSPRNG failed); fall back to
		// the midpoint rather than 0 so behavior stays jittered-ish.
		return n / 2
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	// Modulo bias is negligible here: this only feeds timing jitter.
	return int64(v>>1) % n
}

// dohCacheEntry holds a cached DNS result with its expiry time.
type dohCacheEntry struct {
	addrs  []string
	expiry time.Time
}

// maxDoHCacheEntries bounds the DNS cache so it cannot grow without limit.
const maxDoHCacheEntries = 512

// dohCacheTTL is how long a successful DoH result is cached.
const dohCacheTTL = 5 * time.Minute

// dohResolveTimeout bounds one resolution. It is independent of any caller's
// context, so one impatient caller cannot abort a lookup that others share.
const dohResolveTimeout = 6 * time.Second

// dohAAAAGrace is how long resolve waits for AAAA records once A records are in.
const dohAAAAGrace = 300 * time.Millisecond

// DoHResolver resolves hostnames by querying a DNS-over-HTTPS endpoint (RFC 8484).
type DoHResolver struct {
	client   *http.Client
	endpoint string

	cacheMu  sync.Mutex
	cache    map[string]dohCacheEntry
	lastGood map[string][]string // last successful answer per host, served when a fresh lookup fails
	inflight map[string]*dohFlight
}

// dohFlight lets concurrent lookups for the same host share one set of DoH
// queries instead of each sending its own.
type dohFlight struct {
	done  chan struct{}
	addrs []string
	err   error
}

// wellKnownDoHIPs maps a DoH provider hostname to a fixed IP address. The
// resolver dials that IP directly, so the provider's own name is never
// looked up with system DNS, which would defeat DoH on a poisoned network.
// Providers not listed here must be configured with an IP-literal URL.
var wellKnownDoHIPs = map[string]string{
	"cloudflare-dns.com": "1.1.1.1",
	"dns.cloudflare.com": "1.1.1.1",
	"dns.google":         "8.8.8.8",
}

// NewDoHResolver creates a resolver for the given https:// DoH endpoint. It
// returns an error if the endpoint's host would need system DNS to reach.
func NewDoHResolver(endpoint string) (*DoHResolver, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return nil, errors.New("DoH provider must be an https:// URL")
	}
	host := parsed.Hostname()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	dialContext := dialer.DialContext
	if net.ParseIP(host) == nil {
		knownIP, ok := wellKnownDoHIPs[strings.ToLower(host)]
		if !ok {
			return nil, fmt.Errorf("DoH provider %q is a hostname with no built-in address; use an IP-based DoH URL (for example https://1.1.1.1/dns-query) because resolving it with system DNS would defeat DoH", host)
		}
		dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				return dialer.DialContext(ctx, network, address)
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(knownIP, port))
		}
	}

	return &DoHResolver{
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
				// A fresh connection per query: a pooled DoH connection that
				// went stale would stall the lookup until the timeout.
				DisableKeepAlives: true,
				DialContext:       dialContext,
			},
		},
		endpoint: endpoint,
		cache:    make(map[string]dohCacheEntry),
		lastGood: make(map[string][]string),
		inflight: make(map[string]*dohFlight),
	}, nil
}

// LookupHost resolves a hostname to IP addresses using DoH. Results are
// cached, and concurrent lookups for the same host share one query.
func (r *DoHResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if addrs, ok := r.cacheGet(host); ok {
		return addrs, nil
	}

	r.cacheMu.Lock()
	if flight, ok := r.inflight[host]; ok {
		r.cacheMu.Unlock()
		select {
		case <-flight.done:
			return flight.addrs, flight.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	flight := &dohFlight{done: make(chan struct{})}
	r.inflight[host] = flight
	r.cacheMu.Unlock()

	// The lookup runs on its own timeout, not the caller's context. The caller
	// that started it waits like every other caller and can still leave early.
	go r.runFlight(host, flight)
	select {
	case <-flight.done:
		return flight.addrs, flight.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// runFlight performs one shared lookup. If the lookup fails but an earlier
// answer for the host exists, that answer is returned instead of the error.
func (r *DoHResolver) runFlight(host string, flight *dohFlight) {
	ctx, cancel := context.WithTimeout(context.Background(), dohResolveTimeout)
	defer cancel()
	addrs, err := r.resolve(ctx, host)
	if err == nil {
		r.cacheStore(host, addrs)
	} else if old, ok := r.lastGoodGet(host); ok {
		addrs, err = old, nil
	}
	flight.addrs, flight.err = addrs, err
	r.cacheMu.Lock()
	delete(r.inflight, host)
	r.cacheMu.Unlock()
	close(flight.done)
}

// Refresh re-resolves host now, ignoring the cache, and stores the answer.
// It is used to keep a hot host warm, so real requests rarely wait on DNS.
func (r *DoHResolver) Refresh(ctx context.Context, host string) error {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ctx, cancel := context.WithTimeout(ctx, dohResolveTimeout)
	defer cancel()
	addrs, err := r.resolve(ctx, host)
	if err != nil {
		return err
	}
	r.cacheStore(host, addrs)
	return nil
}

// lastGoodGet returns the last successful answer for host, however old.
func (r *DoHResolver) lastGoodGet(host string) ([]string, bool) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	addrs, ok := r.lastGood[host]
	return addrs, ok && len(addrs) > 0
}

// resolve asks for A and AAAA records in parallel. IPv4 addresses come first
// in the result. It returns as soon as A has answers (AAAA gets a short grace
// period). An error from one record type is reported only when the other type
// also produced nothing.
func (r *DoHResolver) resolve(ctx context.Context, host string) ([]string, error) {
	type lookup struct {
		addrs []string
		err   error
	}
	v4 := make(chan lookup, 1)
	v6 := make(chan lookup, 1)
	go func() {
		addrs, err := r.lookupType(ctx, host, dnsmessage.TypeA)
		v4 <- lookup{addrs, err}
	}()
	go func() {
		addrs, err := r.lookupType(ctx, host, dnsmessage.TypeAAAA)
		v6 <- lookup{addrs, err}
	}()
	var a, aaaa lookup
	a = <-v4
	if a.err == nil && len(a.addrs) > 0 {
		// IPv4 answered. Give AAAA a short grace period, then move on; the
		// straggler is cancelled when the caller's context ends.
		timer := time.NewTimer(dohAAAAGrace)
		select {
		case aaaa = <-v6:
		case <-timer.C:
		}
		timer.Stop()
	} else {
		aaaa = <-v6
	}

	addrs := append(append([]string{}, a.addrs...), aaaa.addrs...)
	if len(addrs) > 0 {
		return addrs, nil
	}
	switch {
	case a.err != nil && aaaa.err != nil:
		return nil, fmt.Errorf("A lookup for %s: %v; AAAA lookup: %w", host, a.err, aaaa.err)
	case a.err != nil:
		return nil, a.err
	case aaaa.err != nil:
		return nil, aaaa.err
	}
	return nil, fmt.Errorf("no DNS records found for %s", host)
}

// cacheGet returns a fresh cached result for host, dropping it if expired.
func (r *DoHResolver) cacheGet(host string) ([]string, bool) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	entry, ok := r.cache[host]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiry) {
		delete(r.cache, host)
		return nil, false
	}
	return entry.addrs, true
}

// cacheStore stores addrs for host. When the cache is full it first removes
// expired entries, then one arbitrary entry if it is still full.
func (r *DoHResolver) cacheStore(host string, addrs []string) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	now := time.Now()
	if len(r.cache) >= maxDoHCacheEntries {
		for key, entry := range r.cache {
			if now.After(entry.expiry) {
				delete(r.cache, key)
			}
		}
	}
	if len(r.cache) >= maxDoHCacheEntries {
		for key := range r.cache {
			delete(r.cache, key)
			break
		}
	}
	r.cache[host] = dohCacheEntry{addrs: addrs, expiry: now.Add(dohCacheTTL)}
	if len(r.lastGood) >= maxDoHCacheEntries {
		for key := range r.lastGood {
			delete(r.lastGood, key)
			break
		}
	}
	r.lastGood[host] = addrs
}

// lookupType sends one DNS query of the given type over DoH and returns the
// addresses in the answer section.
func (r *DoHResolver) lookupType(ctx context.Context, host string, qtype dnsmessage.Type) ([]string, error) {
	if !strings.HasSuffix(host, ".") {
		host = host + "."
	}
	dnsName, err := dnsmessage.NewName(host)
	if err != nil {
		return nil, fmt.Errorf("invalid hostname for DNS query %q: %w", host, err)
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{
			{Name: dnsName, Type: qtype, Class: dnsmessage.ClassINET},
		},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS query: %w", err)
	}

	reqURL := r.endpoint + "?dns=" + base64.RawURLEncoding.EncodeToString(packed)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create DoH request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		// Drop the *url.Error wrapper: it embeds the full DoH URL, which holds
		// the query name.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}

	var response dnsmessage.Message
	if err := response.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack DNS response: %w", err)
	}
	if response.Header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("DNS %v lookup for %s failed: %v", qtype, host, response.Header.RCode)
	}

	var addrs []string
	for _, rr := range response.Answers {
		// Unpack yields pointer bodies. The ResourceBody methods use pointer
		// receivers, so only the pointer types can appear in this switch.
		switch body := rr.Body.(type) {
		case *dnsmessage.AResource:
			addrs = append(addrs, net.IP(body.A[:]).String())
		case *dnsmessage.AAAAResource:
			addrs = append(addrs, net.IP(body.AAAA[:]).String())
		}
	}
	return addrs, nil
}

// workerHTTPError is a non-2xx answer from the Worker. It keeps the status and
// a bounded body snippet, so logs and browser-facing errors say what happened
// (for example "Worker returned HTTP 401: unauthorized") instead of a generic
// retry message.
type workerHTTPError struct {
	StatusCode int
	Snippet    string
}

func (e *workerHTTPError) Error() string {
	if e.Snippet == "" {
		return fmt.Sprintf("Worker returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("Worker returned HTTP %d: %s", e.StatusCode, e.Snippet)
}

// notSentError wraps a p.client.Do failure that is known to have occurred
// before any request bytes reached the wire (no headers were written). Such a
// failure is always safe to retry, even for a non-idempotent method, because
// the origin never saw the request.
type notSentError struct{ err error }

func (e *notSentError) Error() string { return e.err.Error() }
func (e *notSentError) Unwrap() error { return e.err }

// workerErrorSnippet returns a short, single-line excerpt of a Worker error
// body. If the body is the Worker's JSON envelope, its "e" field is preferred.
func workerErrorSnippet(body []byte) string {
	var envelope workerResponse
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Error != "" {
		return truncateForLog(envelope.Error)
	}
	return truncateForLog(string(body))
}

func truncateForLog(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > workerErrorSnippetBytes {
		s = s[:workerErrorSnippetBytes] + "..."
	}
	return s
}

// idleTimeoutReader enforces a stall timeout rather than a total one. If the
// Worker sends nothing for longer than timeout while the body is being read,
// onIdle fires. A large response that keeps moving is never cut off.
type idleTimeoutReader struct {
	r       io.Reader
	timeout time.Duration
	timer   *time.Timer
}

func newIdleTimeoutReader(r io.Reader, timeout time.Duration, onIdle func()) *idleTimeoutReader {
	t := &idleTimeoutReader{r: r, timeout: timeout}
	if timeout > 0 {
		t.timer = time.AfterFunc(timeout, onIdle)
	}
	return t
}

func (t *idleTimeoutReader) Read(p []byte) (int, error) {
	if t.timer != nil {
		t.timer.Reset(t.timeout)
	}
	return t.r.Read(p)
}

func (t *idleTimeoutReader) stop() {
	if t.timer != nil {
		t.timer.Stop()
	}
}

// slotWaitTimeout bounds how long a request waits for a concurrency slot.
const slotWaitTimeout = 30 * time.Second

// errRelaySlotTimeout is returned when no concurrency slot frees up in time.
// It is deliberately not retryable (it wraps no timeout error): the proxy is
// saturated, so repeating the request would only add load.
var errRelaySlotTimeout = errors.New("too many Worker requests in flight; no free slot within 10 s")

// acquireSlot takes one concurrency slot, or waits up to slotWaitTimeout or
// until ctx ends. A slot is held only while an attempt is on the wire. It is
// released before any backoff sleep, so a backing-off request never starves
// the others.
func (p *proxyApp) acquireSlot(ctx context.Context) (func(), error) {
	if p.semaphore == nil {
		return func() {}, nil
	}
	release := func() { <-p.semaphore }
	select {
	case p.semaphore <- struct{}{}:
		return release, nil
	default:
	}
	waitStart := time.Now()
	waitCtx, cancel := context.WithTimeout(ctx, slotWaitTimeout)
	defer cancel()
	select {
	case p.semaphore <- struct{}{}:
		if waited := time.Since(waitStart); waited >= time.Second && p.logs != nil {
			p.logs.add("Proxy", fmt.Sprintf("waited %s for a free relay slot (limit %d)", waited.Round(time.Millisecond), cap(p.semaphore)))
		}
		return release, nil
	case <-waitCtx.Done():
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if p.logs != nil {
			p.logs.add("Proxy", fmt.Sprintf("no relay slot free after %s (limit %d); rejecting the request", slotWaitTimeout, cap(p.semaphore)))
		}
		return nil, errRelaySlotTimeout
	}
}

// hedgeAllowed decides whether a hedge may start now. It never waits: it takes
// a slot without blocking, because a hedge queued behind stuck requests
// defeats its purpose, and it must also fit inside the retry budget. On
// success the caller owns the returned slot and must hand it to attemptRelay
// (heldSlot=true), which releases it.
func (p *proxyApp) hedgeAllowed() bool {
	if p.semaphore != nil {
		select {
		case p.semaphore <- struct{}{}:
		default:
			return false
		}
	}
	if !p.budget.withdraw() {
		if p.semaphore != nil {
			<-p.semaphore
		}
		return false
	}
	return true
}

// attemptRelay performs exactly one POST to one Worker endpoint. It checks the
// HTTP status before anything else, so a 401 or a proxy error page is reported
// as what it is, not as "invalid JSON".
//
// method is the browser's method for the wrapped request. heldSlot means the
// caller already took a concurrency slot (see hedgeAllowed); attemptRelay then
// skips acquiring one and releases the held slot when it returns.
func (p *proxyApp) attemptRelay(ctx context.Context, method, endpoint string, encoded []byte, heldSlot bool) (*http.Response, []byte, error) {
	var release func()
	if heldSlot && p.semaphore != nil {
		release = func() { <-p.semaphore }
	} else if heldSlot {
		release = func() {}
	} else {
		var err error
		release, err = p.acquireSlot(ctx)
		if err != nil {
			return nil, nil, err
		}
	}
	defer release()

	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	request, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if isIdempotentMethod(method) {
		// The wrapped request is a GET/HEAD/OPTIONS, so sending the relay POST
		// twice is harmless. A nil-valued Idempotency-Key tells net/http the
		// POST is replayable, so it retries once on a fresh connection when a
		// pooled one turns out to be dead. Nothing is sent on the wire for it.
		request.Header["Idempotency-Key"] = nil
	}

	// Remember which connection carried this attempt, so an over-age one can
	// be retired as soon as its response is complete.
	var aged atomic.Pointer[agedConn]
	var wrote atomic.Bool
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if tc, ok := info.Conn.(*tls.Conn); ok {
				if ac, ok := tc.NetConn().(*agedConn); ok {
					aged.Store(ac)
				}
			}
		},
		WroteHeaders: func() { wrote.Store(true) },
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))

	response, err := p.client.Do(request)
	if err != nil {
		err = fmt.Errorf("request Worker (%s): %w", endpoint, err)
		if !wrote.Load() && ctx.Err() == nil {
			err = &notSentError{err}
		}
		return nil, nil, err
	}
	defer response.Body.Close()

	var stalled atomic.Bool
	stallTimeout := time.Duration(p.config.requestTimeoutMs) * time.Millisecond
	reader := newIdleTimeoutReader(response.Body, stallTimeout, func() {
		stalled.Store(true)
		cancel()
	})
	defer reader.stop()

	body, readErr := io.ReadAll(io.LimitReader(reader, maxRelayJSON+1))
	if ac := aged.Load(); ac != nil && ac.expired(time.Now()) {
		// Rotation: the response is fully read, so closing now never cuts a
		// request in flight. Only this attempt's own connection is closed;
		// the rest of the idle pool is left alone.
		_ = ac.Close()
	}
	if readErr != nil {
		if stalled.Load() && ctx.Err() == nil {
			// Attempt-level stall, not a caller cancel: report it as a timeout so
			// it is retryable.
			return nil, nil, fmt.Errorf("read Worker response (%s): %w: no data for %s", endpoint, context.DeadlineExceeded, stallTimeout)
		}
		return nil, nil, fmt.Errorf("read Worker response (%s): %w", endpoint, readErr)
	}
	if len(body) > maxRelayJSON {
		return nil, nil, errors.New("Worker response exceeds the 48 MiB JSON limit")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, nil, &workerHTTPError{StatusCode: response.StatusCode, Snippet: workerErrorSnippet(body)}
	}
	return response, body, nil
}

// isRetryableRelayError reports whether a failed attempt to reach the Worker is
// a transient, connection-level failure worth repeating. It uses typed checks
// (errors.Is / errors.As on syscall errors, net.Error, and context and io
// sentinels), not substrings of error text, which differ by OS and Go version.
func isRetryableRelayError(err error) bool {
	if err == nil {
		return false
	}
	// The caller's own cancellation is never retried. Attempt-level timeouts
	// surface as DeadlineExceeded and are retried; sendRelayPayload checks the
	// caller's context separately before deciding.
	if errors.Is(err, context.Canceled) {
		return false
	}
	var cve *tls.CertificateVerificationError
	if errors.As(err, &cve) {
		return false
	}
	var ns *notSentError
	if errors.As(err, &ns) {
		return true
	}
	var whttp *workerHTTPError
	if errors.As(err, &whttp) {
		return isRetryableWorkerHTTPStatus(whttp.StatusCode)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	for _, code := range []syscall.Errno{
		syscall.WSAECONNRESET,
		syscall.WSAECONNABORTED,
		wsaeConnRefused,
		wsaeTimedOut,
		syscall.Errno(64),
		syscall.Errno(121),
		syscall.Errno(10049),
		syscall.Errno(10050),
		syscall.Errno(10051),
		syscall.Errno(10065),
	} {
		if errors.Is(err, code) {
			return true
		}
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// isConnectionRefused reports whether the TCP connect was refused. In that case
// the request never left this machine, so it is safe to retry even when the
// method is not idempotent.
func isConnectionRefused(err error) bool {
	return errors.Is(err, wsaeConnRefused)
}

// isRetryableWorkerHTTPStatus reports whether a Worker status is transient. Only
// 429 and the 502/503/504 gateway statuses are retried. A 500 usually means a
// configuration or code error, and retrying it three times only triples the noise.
func isRetryableWorkerHTTPStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// isIdempotentMethod reports whether method is safe to send twice to the
// origin -- i.e. safe to hedge. GET/HEAD/OPTIONS never have a side effect on
// the origin regardless of how many times they're sent, so relayWithHedge
// may race two of them against two different connections. Every other
// method (POST above all) gets exactly one attempt via relayWithHedge; it
// can still use the existing sequential retry inside sendRelayPayload, since
// that only ever fires after the prior attempt is known to have failed
// before reaching the origin.
func isIdempotentMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

type workerRequest struct {
	Key      string            `json:"k"`
	URL      string            `json:"u"`
	Method   string            `json:"m"`
	Headers  map[string]string `json:"h"`
	Body     string            `json:"b"`
	Redirect bool              `json:"r"`
	// Pad is random, random-length filler the Worker never reads (it only
	// destructures k/u/m/h/b/r -- see worker-decoy.js's `relay()`), so this
	// field is pure padding. Its only purpose is to keep the POST body's
	// on-wire length from being a near-constant function of the wrapped
	// request, since a constant-ish size is itself a classifiable feature.
	Pad string `json:"p,omitempty"`
}

type workerResponse struct {
	Status  int                        `json:"s"`
	Headers map[string]json.RawMessage `json:"h"`
	Body    string                     `json:"b"`
	Error   string                     `json:"e"`
}

type proxyApp struct {
	workerEndpoint string
	// fallbackWorkerEndpoints, when non-empty, holds additional Worker
	// endpoints (each already normalized by parseWorkerURL) that sendRelayPayload
	// cycles through on retries, alongside workerEndpoint. See
	// loadFallbackWorkerEndpoints: this is opt-in via an environment
	// variable, off by default, and never touches proxySettings/the UI.
	fallbackWorkerEndpoints []string
	gatewayKey              string
	client                  *http.Client
	ca                      *localCA
	logs                    *appLogBuffer
	ctx                     context.Context
	cancel                  context.CancelFunc

	// Runtime configuration from proxySettings
	config runtimeConfig

	// Concurrency control
	semaphore chan struct{} // limits concurrent relay requests

	// Retry and hedge budget (see retryBudget).
	budget *retryBudget

	// Statistics
	statsMu           sync.Mutex
	statsRequestCount int64
	statsFailureCount int64
	statsRetryCount   int64

	activeMu sync.Mutex
	active   map[net.Conn]struct{}
	closed   bool
}

// buildRelayPayload turns the browser's request into the JSON payload sent
// to the Worker. It does no network I/O. destination is returned alongside
// encoded so callers can use it later for logging without re-parsing target.
func (p *proxyApp) buildRelayPayload(incoming *http.Request, target string) (encoded []byte, destination *url.URL, err error) {
	cleanTarget, err := validateTargetURL(target)
	if err != nil {
		return nil, nil, err
	}
	destination, err = url.Parse(cleanTarget)
	if err != nil {
		return nil, nil, errors.New("invalid destination URL")
	}
	destHost := strings.TrimSuffix(destination.Hostname(), ".")
	for _, candidate := range append([]string{p.workerEndpoint}, p.fallbackWorkerEndpoints...) {
		gateway, gwErr := url.Parse(candidate)
		if gwErr != nil {
			return nil, nil, errors.New("invalid configured Gateway URL")
		}
		if strings.EqualFold(destHost, strings.TrimSuffix(gateway.Hostname(), ".")) {
			return nil, nil, fmt.Errorf("destination %s is a configured Gateway host; %w", destHost, errRelayLoop)
		}
	}
	var requestBody []byte
	if incoming.Body != nil && incoming.Method != http.MethodGet && incoming.Method != http.MethodHead {
		requestBody, err = io.ReadAll(io.LimitReader(incoming.Body, maxRequestBody+1))
		if err != nil {
			return nil, nil, fmt.Errorf("read browser request body: %w", err)
		}
	}
	if len(requestBody) > maxRequestBody {
		return nil, nil, errRequestBodyTooLarge
	}

	headers := make(map[string]string)
	blocked := map[string]struct{}{
		"host": {}, "connection": {}, "content-length": {}, "transfer-encoding": {},
		"keep-alive": {}, "proxy-authenticate": {}, "proxy-connection": {},
		"proxy-authorization": {}, "te": {}, "trailer": {}, "upgrade": {}, "expect": {},
		"x-medo-relay-token": {}, "x-relay-hop": {}, "x-fwd-hop": {},
	}
	for _, value := range incoming.Header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			blocked[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
		}
	}
	for name, values := range incoming.Header {
		if _, skip := blocked[strings.ToLower(name)]; skip || len(values) == 0 {
			continue
		}
		separator := ", "
		if strings.EqualFold(name, "Cookie") {
			separator = "; "
		}
		headers[name] = strings.Join(values, separator)
	}
	headers["Accept-Encoding"] = "identity"

	payload := workerRequest{
		Key:      p.gatewayKey,
		URL:      cleanTarget,
		Method:   strings.ToUpper(incoming.Method),
		Headers:  headers,
		Body:     base64.StdEncoding.EncodeToString(requestBody),
		Redirect: false,
		Pad:      randomPadding(),
	}
	encoded, err = json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("encode Worker request: %w", err)
	}
	return encoded, destination, nil
}

// randomPadding returns a base64-encoded blob of random length (0..
// relayPaddingMaxBytes of underlying random bytes) for workerRequest.Pad.
// The Worker ignores this field entirely -- see the comment on Pad.
func randomPadding() string {
	n := int(cryptoRandInt63n(relayPaddingMaxBytes + 1))
	if n == 0 {
		return ""
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// sendRelayPayload posts one already-built payload to the Worker and returns
// the Worker's response body. Transient failures are retried on a fresh
// connection (and on the next fallback endpoint, when one is configured),
// subject to the retry budget. Other failures return immediately.
//
// heldSlot means the caller already holds a concurrency slot for the first
// attempt (a hedge); retries acquire their own slots as usual.
func (p *proxyApp) sendRelayPayload(ctx context.Context, method string, encoded []byte, heldSlot bool) (*http.Response, []byte, error) {
	endpoints := append([]string{p.workerEndpoint}, p.fallbackWorkerEndpoints...)

	maxAttempts := 1
	if p.config.enableRetry {
		maxAttempts = p.config.maxRetryAttempts
		if maxAttempts < 1 {
			maxAttempts = 1
		}
	}

	for attempt := 1; ; attempt++ {
		endpoint := endpoints[(attempt-1)%len(endpoints)]
		response, data, attemptErr := p.attemptRelay(ctx, method, endpoint, encoded, heldSlot && attempt == 1)
		if attemptErr == nil {
			return response, data, nil
		}
		if ctx.Err() != nil || attempt >= maxAttempts || !p.shouldRetryAttempt(method, attemptErr) {
			return nil, nil, attemptErr
		}
		if !p.budget.withdraw() {
			return nil, nil, fmt.Errorf("%w (retry budget exhausted; not retrying)", attemptErr)
		}

		p.statsMu.Lock()
		p.statsRetryCount++
		p.statsMu.Unlock()

		if p.logs != nil {
			nextEndpoint := endpoints[attempt%len(endpoints)]
			p.logs.add("Proxy", fmt.Sprintf("%s Worker attempt failed (%v); retrying against %s (attempt %d/%d)", method, attemptErr, nextEndpoint, attempt+1, maxAttempts))
		}

		select {
		case <-time.After(p.calculateBackoff(attempt)):
		case <-ctx.Done():
			return nil, nil, attemptErr
		}
	}
}

// shouldRetryAttempt decides whether a failed attempt may be repeated. A retry
// must never duplicate a side effect at the origin unless the user has
// explicitly accepted that risk.
func (p *proxyApp) shouldRetryAttempt(method string, err error) bool {
	if !isRetryableRelayError(err) {
		return false
	}
	var ns *notSentError
	if errors.As(err, &ns) {
		return true
	}
	if isIdempotentMethod(method) {
		return true
	}
	// Non-idempotent methods: retry only when the request is known not to have
	// reached the origin (connection refused), or when the Worker says it did
	// not run the request (429).
	if isConnectionRefused(err) {
		return true
	}
	var whttp *workerHTTPError
	if errors.As(err, &whttp) && whttp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout() && p.config.retryOnTimeout
}

// calculateBackoff computes the retry delay based on the configured strategy.
// The result never exceeds the configured maximum backoff.
func (p *proxyApp) calculateBackoff(attempt int) time.Duration {
	maxMs := float64(p.config.maxBackoffMs)
	clamp := func(ms float64) time.Duration {
		if maxMs > 0 && ms > maxMs {
			ms = maxMs
		}
		if ms < 0 {
			ms = 0
		}
		return time.Duration(ms * float64(time.Millisecond))
	}
	switch p.config.retryStrategy {
	case "immediate":
		return 0
	case "fixed":
		return clamp(float64(p.config.initialBackoffMs))
	case "exponential":
		// Exponential: initial * multiplier^(attempt-1)
		multiplier := p.config.backoffMultiplier
		if multiplier < 1.0 {
			multiplier = 2.0
		}
		backoffMs := float64(p.config.initialBackoffMs)
		for i := 1; i < attempt; i++ {
			backoffMs *= multiplier
			if maxMs > 0 && backoffMs > maxMs {
				break
			}
		}
		// Add jitter (0-10% of backoff) first, then clamp the total.
		jitterMs := backoffMs * 0.1 * (float64(cryptoRandInt63n(100)) / 100.0)
		return clamp(backoffMs + jitterMs)
	default:
		return clamp(float64(p.config.initialBackoffMs))
	}
}

// finishRelayResponse turns a successful (response, data) pair from
// sendRelayPayload -- or a final error from it -- into the *http.Response
// relayWithHedge used to hand back after its retry loop: validating the Worker's
// JSON envelope, decoding the origin body, rebuilding headers, and logging
// the outcome. destination and started are only used for that final log
// line and are otherwise inert.
func (p *proxyApp) finishRelayResponse(incoming *http.Request, destination *url.URL, started time.Time, response *http.Response, data []byte, sendErr error) (*http.Response, error) {
	if sendErr != nil {
		return nil, sendErr
	}
	if response == nil {
		return nil, errors.New("Worker returned no response")
	}
	var result workerResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("Worker returned a malformed envelope (HTTP %d): %s", response.StatusCode, workerErrorSnippet(data))
	}
	if result.Error != "" {
		return nil, fmt.Errorf("Worker: %s", result.Error)
	}
	if result.Status < 100 || result.Status > 599 {
		return nil, errors.New("Worker response has an invalid origin status")
	}
	decoded, err := base64.StdEncoding.DecodeString(result.Body)
	if err != nil {
		return nil, fmt.Errorf("decode Worker response body: %w", err)
	}
	if len(decoded) > maxResponseBody {
		return nil, errors.New("Worker response body exceeds the 32 MiB limit")
	}

	resultHeaders := make(http.Header)
	preserveRepresentationHeaders := incoming.Method == http.MethodHead || result.Status == http.StatusNotModified
	for name, raw := range result.Headers {
		lower := strings.ToLower(name)
		if lower == "transfer-encoding" || lower == "connection" {
			continue
		}
		// The Fetch Worker retains content-encoding when it passes through a format
		// it cannot decode (for example br or zstd), so the browser can decode it.
		// Content-Length is recalculated below for ordinary response bodies.
		if !preserveRepresentationHeaders && lower == "content-length" {
			continue
		}
		var values []string
		if err := json.Unmarshal(raw, &values); err != nil {
			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				continue
			}
			values = []string{value}
		}
		if strings.EqualFold(name, "Set-Cookie") && len(values) == 1 {
			values = strings.Split(values[0], "\n")
		}
		for _, value := range values {
			resultHeaders.Add(name, value)
		}
	}
	// copyHeaders removes hop-by-hop headers (Keep-Alive, Upgrade, Connection-
	// listed names, and so on) so they are not forwarded to the browser.
	cleanHeaders := make(http.Header, len(resultHeaders))
	copyHeaders(cleanHeaders, resultHeaders)
	resultHeaders = cleanHeaders

	contentLength := int64(len(decoded))
	if result.Status == http.StatusNotModified {
		// A 304 response has no body. Do not forward a representation length from
		// the origin, since Response.Write can reject it against the empty body.
		resultHeaders.Del("Content-Length")
		contentLength = 0
	} else if preserveRepresentationHeaders {
		if rawLength := resultHeaders.Get("Content-Length"); rawLength == "" {
			contentLength = -1
		} else if parsedLength, err := strconv.ParseInt(rawLength, 10, 64); err != nil || parsedLength < 0 {
			resultHeaders.Del("Content-Length")
			contentLength = -1
		} else {
			contentLength = parsedLength
		}
	} else {
		resultHeaders.Set("Content-Length", fmt.Sprint(len(decoded)))
	}
	if p.logs != nil {
		p.logs.add("Proxy", fmt.Sprintf("%s %s returned HTTP %d (%s), %d bytes, %.1f ms", strings.ToUpper(incoming.Method), destination.Host, result.Status, http.StatusText(result.Status), len(decoded), float64(time.Since(started).Microseconds())/1000))
	}
	return &http.Response{
		StatusCode:    result.Status,
		Status:        fmt.Sprintf("%d %s", result.Status, http.StatusText(result.Status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        resultHeaders,
		Body:          io.NopCloser(bytes.NewReader(decoded)),
		ContentLength: contentLength,
		Request:       incoming,
	}, nil
}

// relayWithHedge is the entry point used by ServeHTTP and serveTLSRequests.
//
// For idempotent methods (GET/HEAD/OPTIONS) with hedging enabled, a second
// attempt goes out on a fresh connection if the first has not answered within
// hedgeDelay. The hedge starts only if the retry budget and the concurrency
// limit both allow it, and it never queues for a slot. Non-idempotent methods
// get one attempt and never a hedge, because a duplicated POST can have side
// effects at the origin.
//
// Statistics count one logical request per call, never one per attempt.
func (p *proxyApp) relayWithHedge(ctx context.Context, incoming *http.Request, target string) (*http.Response, error) {
	started := time.Now()

	encoded, destination, err := p.buildRelayPayload(incoming, target)
	if err != nil {
		// Build errors (loop guard, body too large, etc.) are not relay
		// failures and are not counted as requests.
		return nil, err
	}

	p.statsMu.Lock()
	p.statsRequestCount++
	p.statsMu.Unlock()
	p.budget.deposit()

	recordFailure := func(err error) {
		if err != nil && !errors.Is(err, context.Canceled) {
			p.statsMu.Lock()
			p.statsFailureCount++
			p.statsMu.Unlock()
		}
	}
	// finish validates the Worker envelope and counts a failure exactly once,
	// whether it came from the send or from the envelope.
	finish := func(response *http.Response, data []byte, sendErr error) (*http.Response, error) {
		resp, err := p.finishRelayResponse(incoming, destination, started, response, data, sendErr)
		recordFailure(err)
		return resp, err
	}

	if !p.config.enableHedging || !isIdempotentMethod(incoming.Method) || incoming.Header.Get("Range") != "" {
		response, data, sendErr := p.sendRelayPayload(ctx, incoming.Method, encoded, false)
		return finish(response, data, sendErr)
	}

	type outcome struct {
		response *http.Response
		data     []byte
		err      error
	}
	results := make(chan outcome, 2)
	attemptCtx, cancelAttempts := context.WithCancel(ctx)
	defer cancelAttempts()

	launch := func(heldSlot bool) {
		response, data, sendErr := p.sendRelayPayload(attemptCtx, incoming.Method, encoded, heldSlot)
		results <- outcome{response, data, sendErr}
	}
	go launch(false)

	hedgeDelay := time.Duration(p.config.hedgeDelayMs) * time.Millisecond
	hedgeTimer := time.NewTimer(hedgeDelay)
	defer hedgeTimer.Stop()
	hedgeCh := hedgeTimer.C

	pending := 1
	var firstErr error
	for pending > 0 {
		select {
		case r := <-results:
			pending--
			if r.err == nil {
				cancelAttempts() // stop any other attempt; its result is discarded
				return finish(r.response, r.data, nil)
			}
			if firstErr == nil {
				firstErr = r.err
			}
		case <-hedgeCh:
			hedgeCh = nil
			if p.hedgeAllowed() {
				if p.logs != nil {
					p.logs.add("Proxy", fmt.Sprintf("no answer for %s %s within %s; sending a hedge on a second connection", incoming.Method, destination.Host, hedgeDelay))
				}
				pending++
				go launch(true) // hedgeAllowed already took this attempt's slot
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return finish(nil, nil, firstErr)
}

func targetForTLSRequest(request *http.Request, connectHost string) (string, error) {
	if request.URL == nil {
		return "", errors.New("missing HTTPS request URL")
	}
	if request.URL.IsAbs() {
		return validateTargetURL(absoluteTarget(request))
	}
	host := request.Host
	if host == "" {
		host = connectHost
	}
	if host == "" {
		return "", errors.New("missing HTTPS request host")
	}
	if strings.Count(host, ":") > 1 && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	// Use the request line as sent. url.URL.RequestURI re-encodes the path and
	// query, which can change signed URLs.
	requestURI := request.RequestURI
	if !strings.HasPrefix(requestURI, "/") {
		requestURI = request.URL.RequestURI()
	}
	if requestURI == "" {
		requestURI = "/"
	}
	return validateTargetURL("https://" + host + requestURI)
}

func validateTargetURL(raw string) (string, error) {
	target, err := url.ParseRequestURI(raw)
	if err != nil {
		return "", err
	}
	target.Scheme = strings.ToLower(target.Scheme)
	if (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" || target.User != nil {
		return "", errors.New("destination must be an http or https URL")
	}
	// Return the caller's string, not target.String(), so percent-encoding and
	// signed query strings reach the origin unchanged. Only the scheme is
	// normalized, because url.Parse lowercases it.
	if i := strings.Index(raw, ":"); i > 0 {
		return target.Scheme + raw[i:], nil
	}
	return raw, nil
}

// absoluteTarget returns the request target as the client sent it when that is
// an absolute http(s) URL (the normal form for a forward proxy). Otherwise it
// falls back to the parsed URL.
func absoluteTarget(r *http.Request) string {
	lower := strings.ToLower(r.RequestURI)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return r.RequestURI
	}
	return r.URL.String()
}

// logURL returns the part of a URL that is safe to write to logs: scheme, host
// and path. Query strings often carry tokens, so they are dropped.
func logURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "<unparseable URL>"
	}
	return parsed.Scheme + "://" + parsed.Host + parsed.Path
}

// isTimeoutError reports whether err is a network timeout rather than a
// closed connection.
func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// errRequestBodyTooLarge is returned when a browser request body exceeds the
// Gateway limit.
var errRequestBodyTooLarge = errors.New("request body exceeds the 10 MiB Gateway limit")

// errRelayLoop is returned when the browser asks for one of the Gateway's own
// hosts, which would make the proxy relay to itself.
var errRelayLoop = errors.New("refusing a relay loop")

// relayErrorResponse maps a relay error to the status and short message sent
// to the browser. Everything that is not a known client-side or saturation
// condition is a 502.
func relayErrorResponse(err error) (int, string) {
	switch {
	case errors.Is(err, errRequestBodyTooLarge):
		return http.StatusRequestEntityTooLarge, err.Error()
	case errors.Is(err, errRelayLoop):
		return http.StatusMisdirectedRequest, "destination is the Gateway itself; refusing a relay loop"
	case errors.Is(err, errRelaySlotTimeout):
		return http.StatusServiceUnavailable, "proxy is busy; try again shortly"
	default:
		return http.StatusBadGateway, "Cloudflare Worker request failed"
	}
}

// bufferRequestBody reads the browser's request body into memory before the
// relay starts. Afterwards nothing reads the connection while the Worker call
// is in flight, so a watcher can safely read it.
func bufferRequestBody(request *http.Request) error {
	if request.Body == nil || request.Body == http.NoBody {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(request.Body, maxRequestBody+1))
	_ = request.Body.Close()
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	if len(data) > maxRequestBody {
		return errRequestBodyTooLarge
	}
	request.Body = io.NopCloser(bytes.NewReader(data))
	return nil
}

func isUpgradeRequest(headers http.Header) bool {
	if headers.Get("Upgrade") != "" {
		return true
	}
	for _, value := range headers.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

func hostFromAuthority(authority string) (string, error) {
	authority = strings.TrimSpace(authority)
	if host, _, err := net.SplitHostPort(authority); err == nil {
		if host != "" {
			return strings.Trim(host, "[]"), nil
		}
	}
	if authority != "" && strings.Count(authority, ":") == 0 && !strings.ContainsAny(authority, " \t\r\n/@?#") {
		return authority, nil
	}
	return "", errors.New("invalid CONNECT authority")
}

func copyHeaders(destination, source http.Header) {
	blocked := map[string]struct{}{
		"connection": {}, "keep-alive": {}, "proxy-authenticate": {}, "proxy-authorization": {},
		"proxy-connection": {}, "te": {}, "trailer": {}, "transfer-encoding": {}, "upgrade": {},
	}
	for _, value := range source.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			blocked[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
		}
	}
	for name, values := range source {
		if _, skip := blocked[strings.ToLower(name)]; skip {
			continue
		}
		for _, value := range values {
			destination.Add(name, value)
		}
	}
}

type proxyController struct {
	mu       sync.Mutex
	server   *http.Server
	app      *proxyApp
	settings proxySettings
	lastErr  string
	logs     *appLogBuffer
	starting bool // true while start() is running, so two starts cannot overlap
	// stopRequested is set by stop() while a start is in progress, so the
	// start can abandon itself instead of leaving a running proxy behind.
	stopRequested bool
}

// errStartCancelled is returned by start when stop() was called while it ran.
var errStartCancelled = errors.New("start cancelled: the proxy was stopped while it was starting")

// dohFallbackProviders are tried, in order, when the configured DoH provider
// cannot resolve the Worker host at startup.
var dohFallbackProviders = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/dns-query",
	"https://9.9.9.9/dns-query",
}

// dohWorkerRefreshInterval is how often the Worker host is re-resolved in the
// background, a little under the cache TTL, so live traffic rarely waits on DNS.
const dohWorkerRefreshInterval = 4 * time.Minute

// buildBaseDial returns the dial function used for every Worker connection:
// the TCP dialer with short keep-alive probes, wrapped with DoH resolution
// when a resolver is given. Both the running proxy and the Worker check use
// it, so the check takes the same route as real traffic. settings should have
// had applyConfigDefaults applied.
func buildBaseDial(settings proxySettings, resolver *DoHResolver, logs *appLogBuffer) func(ctx context.Context, network, address string) (net.Conn, error) {
	config := settingsToRuntimeConfig(settings)
	dialer := &net.Dialer{
		Timeout: time.Duration(config.dialTimeoutMs) * time.Millisecond,
		// Probe idle connections quickly, so a connection the network silently
		// dropped is noticed in seconds, not after a long TCP timeout.
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     5 * time.Second,
			Interval: 3 * time.Second,
			Count:    3,
		},
	}
	dial := dialer.DialContext
	if resolver == nil {
		return dial
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return dial(ctx, network, address)
		}
		// If it's already an IP, dial directly.
		if net.ParseIP(host) != nil {
			return dial(ctx, network, address)
		}
		// Use DoH to resolve the hostname. System DNS is never used as a
		// fallback, so lookups do not leak.
		ips, err := resolver.LookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DoH lookup failed for %s (system DNS fallback disabled): %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("DoH returned no addresses for %s", host)
		}
		// Try each resolved IP.
		var lastErr error
		for _, ip := range ips {
			conn, err := dial(ctx, network, net.JoinHostPort(ip, port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, fmt.Errorf("all DoH-resolved addresses failed for %s: %w", host, lastErr)
	}
}

// selectDoHResolver builds the DoH resolver and proves it can resolve the
// Worker host. If the configured provider fails, the built-in fallbacks are
// tried in turn. It returns an error if none of them can.
func selectDoHResolver(settings proxySettings, workerHost string, logs *appLogBuffer) (*DoHResolver, error) {
	candidates := []string{settings.DoHProvider}
	for _, fallback := range dohFallbackProviders {
		if fallback != settings.DoHProvider {
			candidates = append(candidates, fallback)
		}
	}
	var lastErr error
	for i, provider := range candidates {
		resolver, err := NewDoHResolver(provider)
		if err != nil {
			if i == 0 {
				return nil, err // a configuration problem, not a network one
			}
			lastErr = err
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		_, err = resolver.LookupHost(ctx, workerHost)
		cancel()
		if err == nil {
			if logs != nil {
				if i == 0 {
					logs.add("Proxy", fmt.Sprintf("DNS over HTTPS enabled: %s", provider))
				} else {
					logs.add("Proxy", fmt.Sprintf("DNS over HTTPS provider %s could not resolve %s; using fallback %s", settings.DoHProvider, workerHost, provider))
				}
			}
			return resolver, nil
		}
		lastErr = err
		if logs != nil {
			logs.add("Proxy", fmt.Sprintf("DoH provider %s failed to resolve %s: %v", provider, workerHost, err))
		}
	}
	return nil, fmt.Errorf("DNS over HTTPS could not resolve %s through any provider (%v); turn DoH off or check the network", workerHost, lastErr)
}

type statusSnapshot struct {
	Running              bool   `json:"running"`
	ProxyAddress         string `json:"proxyAddress"`
	WorkerURL            string `json:"workerURL"`
	CACertPath           string `json:"caCertPath"`
	CloudflareAccountID  string `json:"cloudflareAccountId"`
	CloudflareWorkerName string `json:"cloudflareWorker"`
	CloudflareFetchName  string `json:"cloudflareFetchWorker"`
	LastError            string `json:"lastError"`
}

func (c *proxyController) start(settings proxySettings, gatewayKey string) (string, error) {
	if gatewayKey == "" {
		return "", errors.New("enter the Gateway password")
	}

	// Claim the start slot under the lock. Checking c.server and assigning it
	// later, with the lock released in between, let two starts overlap.
	c.mu.Lock()
	if c.server != nil || c.starting {
		c.mu.Unlock()
		return "", errors.New("local proxy is already running or starting; stop it first")
	}
	c.starting = true
	c.stopRequested = false
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.starting = false
		c.mu.Unlock()
	}()

	// Apply defaults to any missing configuration fields
	applyConfigDefaults(&settings)

	// Convert settings to runtime config
	config := settingsToRuntimeConfig(settings)

	endpoint, err := parseWorkerURL(settings.WorkerURL)
	if err != nil {
		return "", err
	}
	if err := validateLoopbackAddress(settings.ListenAddress); err != nil {
		return "", err
	}
	ca, err := loadCA(settings.CACertPath, settings.CAKeyPath)
	if err != nil {
		return "", err
	}
	workerTLSConfig, err := loadWorkerTLSConfig(settings.WorkerCACertPath)
	if err != nil {
		return "", err
	}

	// Enable DoH (DNS over HTTPS) if configured. The Worker host is resolved
	// once up front, with fallback providers, so a bad provider fails Start
	// with a clear message instead of failing every request later.
	var dohResolver *DoHResolver
	workerHost := ""
	if parsedEndpoint, perr := url.Parse(endpoint); perr == nil {
		workerHost = parsedEndpoint.Hostname()
	}
	if settings.DoHEnabled && settings.DoHProvider != "" {
		if config.cdnEdgeIP != "" || net.ParseIP(workerHost) != nil {
			// The Worker is dialed by IP, so no lookup is needed for it.
			dohResolver, err = NewDoHResolver(settings.DoHProvider)
			if err != nil {
				return "", err
			}
			if c.logs != nil {
				c.logs.add("Proxy", fmt.Sprintf("DNS over HTTPS enabled: %s", settings.DoHProvider))
			}
		} else {
			dohResolver, err = selectDoHResolver(settings, workerHost, c.logs)
			if err != nil {
				return "", err
			}
		}
	}
	baseDialContext := buildBaseDial(settings, dohResolver, c.logs)

	connTracker := newConnAgeTracker()
	transport := newWorkerTransport(config, workerTLSConfig, baseDialContext, connTracker)

	// Apply ALPN configuration if provided
	if len(config.alpnProtocols) > 0 {
		if workerTLSConfig == nil {
			workerTLSConfig = &tls.Config{}
		}
		// Set ALPN protocols (this mutates the config, which is fine since we're about to use it)
		workerTLSConfig.NextProtos = config.alpnProtocols
		transport.TLSClientConfig = workerTLSConfig
	}

	fallbackEndpoints := loadFallbackWorkerEndpoints(endpoint)
	if len(fallbackEndpoints) > 0 && c.logs != nil {
		c.logs.add("Proxy", fmt.Sprintf("%d fallback Worker endpoint(s) loaded from %s; retries will rotate across all %d endpoints", len(fallbackEndpoints), medovpnFallbackWorkerURLsEnv, 1+len(fallbackEndpoints)))
	}

	// Log the configuration that is actually in effect.
	if c.logs != nil {
		c.logs.add("Proxy", fmt.Sprintf("Relay endpoint: %s", endpoint))
		c.logs.add("Proxy", fmt.Sprintf("Config: retry=%t attempts=%d hedge=%t rotate=%t frag=%t reuse=%t idle=%ds",
			config.enableRetry, config.maxRetryAttempts, config.enableHedging, config.enableConnectionRotation,
			config.enableFragmentation, config.enableConnectionReuse, config.idleConnTimeoutSec))
		features := []string{}
		if config.enableConnectionRotation {
			features = append(features, fmt.Sprintf("connection rotation (%ds)", config.connectionMaxAgeSec))
		}
		if config.enableFragmentation {
			features = append(features, fmt.Sprintf("ClientHello fragmentation (%d pieces)", config.fragmentPieces))
		}
		if config.enableHedging {
			features = append(features, fmt.Sprintf("hedged requests (%dms)", config.hedgeDelayMs))
		}
		if config.enableRetry {
			features = append(features, fmt.Sprintf("retry (%d attempts, %s)", config.maxRetryAttempts, config.retryStrategy))
		}
		if config.cdnEdgeIP != "" {
			features = append(features, fmt.Sprintf("CDN edge IP override: %s", config.cdnEdgeIP))
		}
		if settings.DoHEnabled && settings.DoHProvider != "" {
			features = append(features, "DNS over HTTPS")
		}
		if len(features) > 0 {
			c.logs.add("Proxy", "Active DPI evasion: "+strings.Join(features, ", "))
		} else {
			c.logs.add("Proxy", "Warning: All DPI evasion features disabled")
		}
		if !config.enableRetry && !config.enableHedging {
			c.logs.add("Proxy", "Warning: retry and hedging are both off, so a dead Worker connection goes straight to the browser as an error")
		}
	}

	appContext, appCancel := context.WithCancel(context.Background())

	// Build semaphore for concurrent request limiting
	limitConcurrency := config.enableConnectionPool && settings.MaxConcurrentRequests > 0
	var semaphore chan struct{}
	if limitConcurrency {
		semaphore = make(chan struct{}, settings.MaxConcurrentRequests)
		if c.logs != nil {
			c.logs.add("Proxy", fmt.Sprintf("Concurrent request limit: %d", settings.MaxConcurrentRequests))
		}
	}

	if limitConcurrency {
		// Headroom above the semaphore, so a hedge or retry can dial without
		// queueing behind the connections it is working around.
		transport.MaxConnsPerHost = 2 * settings.MaxConcurrentRequests
	}

	app := &proxyApp{
		workerEndpoint:          endpoint,
		fallbackWorkerEndpoints: fallbackEndpoints,
		gatewayKey:              gatewayKey,
		client: &http.Client{
			Transport: transport,

			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse // Never follow redirects; return the response as-is
			},
		},
		ca:        ca,
		logs:      c.logs,
		ctx:       appContext,
		cancel:    appCancel,
		config:    config,
		semaphore: semaphore,
		budget:    newRetryBudget(),
		active:    make(map[net.Conn]struct{}),
	}
	if dohResolver != nil && workerHost != "" && config.cdnEdgeIP == "" && net.ParseIP(workerHost) == nil {
		// Keep the Worker host's address fresh in the background.
		go func() {
			ticker := time.NewTicker(dohWorkerRefreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-appContext.Done():
					return
				case <-ticker.C:
					if err := dohResolver.Refresh(appContext, workerHost); err != nil && appContext.Err() == nil && c.logs != nil {
						c.logs.add("Proxy", fmt.Sprintf("background DoH refresh of %s failed (keeping the last good address): %v", workerHost, err))
					}
				}
			}
		}()
	}
	listener, err := net.Listen("tcp", settings.ListenAddress)
	if err != nil {
		appCancel()
		transport.CloseIdleConnections()
		return "", fmt.Errorf("listen on %s: %w", settings.ListenAddress, err)
	}
	server := &http.Server{
		Addr:              listener.Addr().String(),
		Handler:           app,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	c.mu.Lock()
	if c.stopRequested {
		c.stopRequested = false
		c.mu.Unlock()
		_ = listener.Close()
		appCancel()
		transport.CloseIdleConnections()
		return "", errStartCancelled
	}
	c.server = server
	c.app = app
	c.settings = settings
	c.lastErr = ""
	c.mu.Unlock()

	go func() {
		serveErr := server.Serve(listener)
		if serveErr == nil || errors.Is(serveErr, http.ErrServerClosed) {
			return
		}
		_ = server.Close()
		app.closeActiveConnections()
		app.client.CloseIdleConnections()
		c.mu.Lock()
		if c.server == server {
			c.server = nil
			c.app = nil
			c.lastErr = "proxy stopped unexpectedly: " + serveErr.Error()
		}
		c.mu.Unlock()
	}()
	return listener.Addr().String(), nil
}

func (c *proxyController) stop() {
	c.mu.Lock()
	if c.starting {
		// A start is in progress and has not published its server yet; tell
		// it to abandon itself.
		c.stopRequested = true
	}
	server, app := c.server, c.app
	c.server, c.app = nil, nil
	c.lastErr = ""
	c.mu.Unlock()
	if app != nil {
		app.closeActiveConnections()
		app.client.CloseIdleConnections()
	}
	if server != nil {
		_ = server.Close()
	}
}

func (c *proxyController) snapshot() statusSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	snapshot := statusSnapshot{
		Running:              c.server != nil,
		WorkerURL:            c.settings.WorkerURL,
		CACertPath:           c.settings.CACertPath,
		CloudflareAccountID:  c.settings.CloudflareAccountID,
		CloudflareWorkerName: c.settings.CloudflareWorker,
		CloudflareFetchName:  c.settings.CloudflareFetchWorker,
		LastError:            c.lastErr,
	}
	if c.server != nil {
		snapshot.ProxyAddress = c.server.Addr
	}
	return snapshot
}

func (p *proxyApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	if isUpgradeRequest(r.Header) {
		http.Error(w, "WebSocket upgrades are not supported by the Worker fetch relay", http.StatusNotImplemented)
		return
	}
	if r.URL == nil || !r.URL.IsAbs() || (r.URL.Scheme != "http" && r.URL.Scheme != "https") {
		http.Error(w, "proxy expects an absolute http:// or https:// URL", http.StatusBadRequest)
		return
	}
	response, err := p.relayWithHedge(r.Context(), r, absoluteTarget(r))
	if err != nil {
		if errors.Is(err, context.Canceled) {
			// The browser went away; there is nobody to answer.
			return
		}
		// Logging the target alongside the error is what makes a "refusing a
		// relay loop" line diagnosable: that guard only fires when the
		// browser's own request target is literally the Gateway's own host
		// (visiting the decoy site through the proxy, a bookmark/prefetch of
		// it, etc.), and without the target you can't tell that from a real
		// failure at a glance.
		log.Printf("HTTP relay failed for %s: %v", logURL(absoluteTarget(r)), err)
		status, message := relayErrorResponse(err)
		http.Error(w, message, status)
		return
	}
	defer response.Body.Close()
	copyHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func (p *proxyApp) trackConnection(conn net.Conn) bool {
	p.activeMu.Lock()
	defer p.activeMu.Unlock()
	if p.closed {
		return false
	}
	if p.active == nil {
		p.active = make(map[net.Conn]struct{})
	}
	p.active[conn] = struct{}{}
	return true
}

func (p *proxyApp) untrackConnection(conn net.Conn) {
	p.activeMu.Lock()
	delete(p.active, conn)
	p.activeMu.Unlock()
}

func (p *proxyApp) closeActiveConnections() {
	p.activeMu.Lock()
	p.closed = true
	cancel := p.cancel
	active := make([]net.Conn, 0, len(p.active))
	for conn := range p.active {
		active = append(active, conn)
	}
	p.active = nil
	p.activeMu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, conn := range active {
		_ = conn.Close()
	}
}

func (ui *controlUI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
	if !ui.allowedOrigin(r.Host) {
		http.Error(w, "host rejected", http.StatusMisdirectedRequest)
		return
	}

	switch r.URL.Path {
	case "/":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		ui.settingsMu.RLock()
		defaults := ui.defaults
		ui.settingsMu.RUnlock()
		data := struct {
			Defaults           proxySettings
			UIToken            string
			HasGatewayKey      bool
			HasCloudflareToken bool
		}{defaults, ui.uiToken, ui.hasInitialGatewayKey(), ui.hasCloudflareToken()}
		if err := controlPage.Execute(w, data); err != nil {
			http.Error(w, "could not render control panel", http.StatusInternalServerError)
		}
	case "/api/status":
		if r.Method != http.MethodGet {
			writeUIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !ui.authorized(w, r) {
			return
		}
		writeUIJSON(w, http.StatusOK, ui.controller.snapshot())
	case "/api/logs":
		if r.Method != http.MethodGet {
			writeUIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !ui.authorized(w, r) {
			return
		}
		after := uint64(0)
		if raw := r.URL.Query().Get("after"); raw != "" {
			parsed, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				writeUIError(w, http.StatusBadRequest, "invalid log cursor")
				return
			}
			after = parsed
		}
		writeUIJSON(w, http.StatusOK, ui.logs.since(after))
	case "/api/worker-check":
		if r.Method != http.MethodPost {
			writeUIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !ui.authorized(w, r) {
			return
		}
		var input struct {
			WorkerURL        string         `json:"workerURL"`
			WorkerCACertPath string         `json:"workerCACertPath"`
			GatewayKey       string         `json:"gatewayKey"`
			Settings         *proxySettings `json:"settings"`
		}
		if err := decodeUIJSON(w, r, &input); err != nil {
			writeUIError(w, http.StatusBadRequest, err.Error())
			return
		}
		gatewayKey := strings.TrimSpace(input.GatewayKey)
		if gatewayKey == "" {
			ui.tokenMu.Lock()
			gatewayKey = ui.initialGatewayKey
			ui.tokenMu.Unlock()
		}
		// Probe with the values posted from the form, so the check matches
		// what Start would use; fall back to the saved settings if the page
		// did not send any.
		var probeSettings proxySettings
		if input.Settings != nil {
			probeSettings = *input.Settings
		} else {
			probeSettings = ui.currentSettings()
		}
		probeSettings.SettingsVersion = settingsVersion
		normalizeSettings(&probeSettings)
		applyConfigDefaults(&probeSettings)
		// Room for /health, one retry of it, and the relay test.
		healthTimeout := time.Duration(probeSettings.HealthCheckTimeout) * time.Second
		if healthTimeout <= 0 {
			healthTimeout = 10 * time.Second
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*healthTimeout+5*time.Second)
		result := checkWorker(ctx, input.WorkerURL, input.WorkerCACertPath, gatewayKey, probeSettings)
		cancel()
		switch {
		case !result.Reachable:
			ui.logs.add("Worker check", "GET /health failed: "+result.Error)
		case result.RelayTested && result.RelayOK:
			ui.logs.add("Worker check", fmt.Sprintf("GET /health returned HTTP %d, latency %.1f ms; relay test passed", result.Status, result.LatencyMS))
		case result.RelayTested:
			ui.logs.add("Worker check", fmt.Sprintf("GET /health returned HTTP %d; relay test failed: %s", result.Status, result.RelayError))
		default:
			ui.logs.add("Worker check", fmt.Sprintf("GET /health returned HTTP %d, latency %.1f ms (no Worker password; relay not tested)", result.Status, result.LatencyMS))
		}
		writeUIJSON(w, http.StatusOK, result)
	case "/api/stats":
		if r.Method != http.MethodGet {
			writeUIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !ui.authorized(w, r) {
			return
		}
		// Return stats from the active proxy
		stats := map[string]interface{}{
			"totalRequests":  int64(0),
			"failedRequests": int64(0),
			"retryCount":     int64(0),
			"successRate":    float64(100),
			"running":        false,
		}
		ui.controller.mu.Lock()
		if ui.controller.app != nil {
			app := ui.controller.app
			app.statsMu.Lock()
			total := app.statsRequestCount
			failed := app.statsFailureCount
			retries := app.statsRetryCount
			app.statsMu.Unlock()

			successRate := 100.0
			if total > 0 {
				successRate = float64(total-failed) / float64(total) * 100.0
			}

			stats = map[string]interface{}{
				"totalRequests":  total,
				"failedRequests": failed,
				"retryCount":     retries,
				"successRate":    successRate,
				"running":        true,
			}
		}
		ui.controller.mu.Unlock()
		writeUIJSON(w, http.StatusOK, stats)
	case "/api/worker-ca":
		if r.Method != http.MethodPost {
			writeUIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !ui.authorized(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxWorkerCACertSize+(64<<10))
		if err := r.ParseMultipartForm(maxWorkerCACertSize); err != nil {
			writeUIError(w, http.StatusBadRequest, "select a valid certificate file under 1 MiB")
			return
		}
		if r.MultipartForm != nil {
			defer r.MultipartForm.RemoveAll()
		}
		file, _, err := r.FormFile("certificate")
		if err != nil {
			writeUIError(w, http.StatusBadRequest, "select a Worker CA certificate file")
			return
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, maxWorkerCACertSize+1))
		if err != nil {
			writeUIError(w, http.StatusBadRequest, "could not read uploaded certificate")
			return
		}
		if len(data) == 0 || len(data) > maxWorkerCACertSize {
			writeUIError(w, http.StatusBadRequest, "certificate file must be between 1 byte and 1 MiB")
			return
		}
		if _, err := parseWorkerCACertificates(data); err != nil {
			writeUIError(w, http.StatusBadRequest, err.Error())
			return
		}
		path, err := storeWorkerCACertificate(ui.settingsFile, data)
		if err != nil {
			writeUIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		ui.settingsMu.Lock()
		updated := ui.defaults
		updated.WorkerCACertPath = path
		if err := saveSettings(ui.settingsFile, updated); err != nil {
			ui.settingsMu.Unlock()
			writeUIError(w, http.StatusInternalServerError, "save certificate setting: "+err.Error())
			return
		}
		ui.defaults = updated
		ui.settingsMu.Unlock()
		ui.logs.add("Worker check", "Worker TLS CA certificate uploaded and saved")
		writeUIJSON(w, http.StatusOK, map[string]string{"path": path})
	case "/api/start":
		if r.Method != http.MethodPost {
			writeUIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !ui.authorized(w, r) {
			return
		}
		var input startRequest
		if err := decodeUIJSON(w, r, &input); err != nil {
			writeUIError(w, http.StatusBadRequest, err.Error())
			return
		}
		input.Settings.SettingsVersion = settingsVersion
		input.Settings.WorkerURL = strings.TrimSpace(input.Settings.WorkerURL)
		input.Settings.ListenAddress = strings.TrimSpace(input.Settings.ListenAddress)
		input.Settings.CACertPath = strings.TrimSpace(input.Settings.CACertPath)
		input.Settings.CAKeyPath = strings.TrimSpace(input.Settings.CAKeyPath)
		input.Settings.WorkerCACertPath = strings.TrimSpace(input.Settings.WorkerCACertPath)
		input.Settings.CloudflareAccountID = strings.TrimSpace(input.Settings.CloudflareAccountID)
		input.Settings.CloudflareWorker = strings.TrimSpace(input.Settings.CloudflareWorker)
		input.Settings.CloudflareFetchWorker = strings.TrimSpace(input.Settings.CloudflareFetchWorker)
		normalizeSettings(&input.Settings)

		if err := validateStartSettings(input.Settings); err != nil {
			writeUIError(w, http.StatusBadRequest, err.Error())
			return
		}
		input.GatewayKey = strings.TrimSpace(input.GatewayKey)
		if input.GatewayKey == "" {
			ui.tokenMu.Lock()
			input.GatewayKey = ui.initialGatewayKey
			ui.tokenMu.Unlock()
		}

		// Start the proxy first - only save settings if it succeeds
		address, err := ui.controller.start(input.Settings, input.GatewayKey)
		if err != nil {
			ui.logs.add("Proxy", "Could not start: "+err.Error())
			writeUIError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Proxy started successfully - apply defaults and persist settings and key
		// Apply defaults so saved settings match what's used at runtime
		applyConfigDefaults(&input.Settings)

		if err := saveSettings(ui.settingsFile, input.Settings); err != nil {
			ui.logs.add("Proxy", "Warning: proxy started but settings not saved: "+err.Error())
			// Don't fail the request - proxy is running
		}
		if input.GatewayKey != "" {
			if err := saveGatewayKey(ui.gatewayKeyPath, input.GatewayKey); err != nil {
				ui.logs.add("Proxy", "Warning: proxy started but password not saved: "+err.Error())
				// Don't fail the request - proxy is running
			}
			ui.tokenMu.Lock()
			ui.initialGatewayKey = input.GatewayKey
			ui.tokenMu.Unlock()
		}

		ui.settingsMu.Lock()
		ui.defaults = input.Settings
		ui.settingsMu.Unlock()
		relayTarget := input.Settings.WorkerURL
		if normalized, nerr := parseWorkerURL(input.Settings.WorkerURL); nerr == nil {
			relayTarget = normalized
		}
		ui.logs.add("Proxy", "Started at "+address+"; HTTPS relay target is "+relayTarget)
		writeUIJSON(w, http.StatusOK, map[string]string{"proxyAddress": address})
	case "/api/stop":
		if r.Method != http.MethodPost {
			writeUIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !ui.authorized(w, r) {
			return
		}
		ui.controller.stop()
		ui.logs.add("Proxy", "Stopped")
		writeUIJSON(w, http.StatusOK, map[string]bool{"running": false})
	case "/api/save-config":
		if r.Method != http.MethodPost {
			writeUIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !ui.authorized(w, r) {
			return
		}
		var input startRequest
		if err := decodeUIJSON(w, r, &input); err != nil {
			writeUIError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Trim and validate basic settings
		input.Settings.WorkerURL = strings.TrimSpace(input.Settings.WorkerURL)
		input.Settings.ListenAddress = strings.TrimSpace(input.Settings.ListenAddress)
		input.Settings.CACertPath = strings.TrimSpace(input.Settings.CACertPath)
		input.Settings.CAKeyPath = strings.TrimSpace(input.Settings.CAKeyPath)
		input.Settings.WorkerCACertPath = strings.TrimSpace(input.Settings.WorkerCACertPath)
		input.Settings.SettingsVersion = settingsVersion
		normalizeSettings(&input.Settings)
		if err := validateStartSettings(input.Settings); err != nil {
			writeUIError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Apply defaults and save the configuration
		applyConfigDefaults(&input.Settings)
		if err := saveSettings(ui.settingsFile, input.Settings); err != nil {
			writeUIError(w, http.StatusInternalServerError, "save settings: "+err.Error())
			return
		}

		// Update the defaults in-memory
		ui.settingsMu.Lock()
		ui.defaults = input.Settings
		ui.settingsMu.Unlock()

		ui.logs.add("Proxy", "Configuration saved")
		writeUIJSON(w, http.StatusOK, map[string]string{"message": "Configuration saved"})
	case "/api/cloudflare-logs/status":
		if r.Method != http.MethodGet {
			writeUIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !ui.authorized(w, r) {
			return
		}
		writeUIJSON(w, http.StatusOK, ui.tail.Status())
	case "/api/cloudflare-logs/start":
		if r.Method != http.MethodPost {
			writeUIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !ui.authorized(w, r) {
			return
		}
		var input startTailRequest
		if err := decodeUIJSON(w, r, &input); err != nil {
			writeUIError(w, http.StatusBadRequest, err.Error())
			return
		}
		input.AccountID = strings.TrimSpace(input.AccountID)
		input.GatewayWorker = strings.TrimSpace(input.GatewayWorker)
		input.FetchWorker = strings.TrimSpace(input.FetchWorker)
		input.Token = strings.TrimSpace(input.Token)
		if !accountIDPattern.MatchString(input.AccountID) {
			writeUIError(w, http.StatusBadRequest, "enter a 32-character Cloudflare account ID")
			return
		}
		if !workerNamePattern.MatchString(input.GatewayWorker) {
			writeUIError(w, http.StatusBadRequest, "Worker name may contain letters, numbers, hyphens, and underscores")
			return
		}
		if !workerNamePattern.MatchString(input.FetchWorker) {
			writeUIError(w, http.StatusBadRequest, "Fetch Worker name may contain letters, numbers, hyphens, and underscores")
			return
		}
		if strings.EqualFold(input.GatewayWorker, input.FetchWorker) {
			writeUIError(w, http.StatusBadRequest, "Gateway and Fetch Worker names must be different")
			return
		}
		if input.Token == "" {
			ui.cloudflareTokenMu.Lock()
			input.Token = ui.cloudflareToken
			ui.cloudflareTokenMu.Unlock()
		}
		if input.Token == "" {
			writeUIError(w, http.StatusBadRequest, "enter a Cloudflare API token")
			return
		}
		if input.Remember {
			if err := saveCloudflareToken(ui.cloudflareTokenPath, input.Token); err != nil {
				writeUIError(w, http.StatusInternalServerError, "save Cloudflare token: "+err.Error())
				return
			}
		}
		settings := ui.currentSettings()
		settings.CloudflareAccountID = input.AccountID
		settings.CloudflareWorker = input.GatewayWorker
		settings.CloudflareFetchWorker = input.FetchWorker
		if err := saveSettings(ui.settingsFile, settings); err != nil {
			writeUIError(w, http.StatusInternalServerError, "save Cloudflare settings: "+err.Error())
			return
		}
		ui.settingsMu.Lock()
		ui.defaults = settings
		ui.settingsMu.Unlock()
		ui.cloudflareTokenMu.Lock()
		ui.cloudflareToken = input.Token
		ui.cloudflareTokenMu.Unlock()
		if err := ui.tail.Start(input.AccountID, input.GatewayWorker, input.FetchWorker, input.Token); err != nil {
			writeUIError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeUIJSON(w, http.StatusOK, ui.tail.Status())
	case "/api/cloudflare-logs/stop":
		if r.Method != http.MethodPost {
			writeUIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !ui.authorized(w, r) {
			return
		}
		ui.tail.Stop()
		writeUIJSON(w, http.StatusOK, ui.tail.Status())
	default:
		http.NotFound(w, r)
	}
}

type workerCheckResult struct {
	Reachable   bool      `json:"reachable"`
	Healthy     bool      `json:"healthy"`
	Status      int       `json:"status"`
	Meaning     string    `json:"meaning"`
	LatencyMS   float64   `json:"latencyMs"`
	Body        string    `json:"body"`
	URL         string    `json:"url"`
	CheckedAt   time.Time `json:"checkedAt"`
	Error       string    `json:"error"`
	RelayTested bool      `json:"relayTested"`
	RelayOK     bool      `json:"relayOK"`
	RelayStatus int       `json:"relayStatus,omitempty"`
	RelayError  string    `json:"relayError,omitempty"`
}

// relayProbeURL is the public URL the health check asks the Gateway to fetch.
// It answers 204 with no body. /health alone cannot show whether relaying
// works, so the check also sends this request through /relay.
const relayProbeURL = "https://www.gstatic.com/generate_204"

// checkWorker verifies the Gateway in two steps. It first fetches /health over
// the same transport the relay uses. If the Gateway password is known, it then
// sends one real request through /relay. The Gateway forwards that request to
// the Fetch Worker, so a passing relay test covers both Workers.
//
// settings are the values currently shown in the form, so the check exercises
// what Start would use. Its timeouts derive from HealthCheckTimeout.
func checkWorker(ctx context.Context, rawURL, workerCACertPath, gatewayKey string, settings proxySettings) workerCheckResult {
	result := workerCheckResult{Meaning: "No HTTP response received", CheckedAt: time.Now().UTC()}
	config := settingsToRuntimeConfig(settings)
	healthTimeout := time.Duration(settings.HealthCheckTimeout) * time.Second
	if healthTimeout <= 0 {
		healthTimeout = 10 * time.Second
	}
	endpoint, err := parseWorkerURL(rawURL)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		result.Error = "invalid Worker URL"
		return result
	}
	parsed.Path = "/health"
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	result.URL = parsed.String()
	tlsConfig, err := loadWorkerTLSConfig(workerCACertPath)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if len(config.alpnProtocols) > 0 {
		cloned := tlsConfig.Clone()
		if cloned == nil {
			cloned = &tls.Config{}
		}
		cloned.NextProtos = config.alpnProtocols
		tlsConfig = cloned
	}

	probeConfig := config
	probeConfig.enableConnectionRotation = false
	probeConfig.tlsHandshakeTimeoutMs = int(healthTimeout / time.Millisecond)
	probeConfig.responseHeaderTimeoutMs = int(healthTimeout / time.Millisecond)

	// Same dial builder as the running proxy, so the probe uses the same DNS
	// (including DNS over HTTPS), dialing, fragmentation and TLS route.
	var resolver *DoHResolver
	if settings.DoHEnabled && settings.DoHProvider != "" {
		resolver, err = NewDoHResolver(settings.DoHProvider)
		if err != nil {
			result.Error = err.Error()
			return result
		}
	}
	transport := newWorkerTransport(probeConfig, tlsConfig, buildBaseDial(settings, resolver, nil), nil)
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   healthTimeout + healthTimeout/2,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	// /health is retried once if the first try times out: the first dial after
	// a quiet period is the one most likely to hit a dead path.
	var response *http.Response
	started := time.Now()
	for attempt := 1; ; attempt++ {
		request, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, result.URL, nil)
		if reqErr != nil {
			result.Error = "could not create Worker health request"
			return result
		}
		request.Header.Set("Accept", "text/plain")
		request.Header.Set("Cache-Control", "no-cache")

		started = time.Now()
		var doErr error
		response, doErr = client.Do(request)
		if doErr == nil {
			break
		}
		if attempt == 1 && ctx.Err() == nil && (isTimeoutError(doErr) || errors.Is(doErr, context.DeadlineExceeded)) {
			continue
		}
		result.LatencyMS = float64(time.Since(started).Microseconds()) / 1000
		result.Error = doErr.Error()
		return result
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	result.LatencyMS = float64(time.Since(started).Microseconds()) / 1000
	result.Reachable = true
	result.Status = response.StatusCode
	result.Meaning = httpStatusMeaning(response.StatusCode)
	if len(body) > 4096 {
		body = append(body[:4096], []byte(" …[response truncated]")...)
	}
	result.Body = strings.TrimSpace(string(body))
	if readErr != nil {
		result.Error = "read Worker health response: " + readErr.Error()
		return result
	}
	if response.StatusCode != http.StatusOK {
		return result
	}

	gatewayKey = strings.TrimSpace(gatewayKey)
	if gatewayKey == "" {
		result.Meaning = "200 OK — /health answered. Enter the Worker password to test the relay path too."
		return result
	}
	result.RelayTested = true
	relayStatus, relayErr := probeRelay(ctx, client, endpoint, gatewayKey)
	result.RelayStatus = relayStatus
	if relayErr != nil {
		result.RelayError = relayErr.Error()
		result.Meaning = "200 OK — /health answered, but the relay test failed: " + relayErr.Error()
		return result
	}
	result.RelayOK = true
	result.Healthy = true
	result.Meaning = "200 OK — the Gateway relayed a test request through the Fetch Worker"
	return result
}

// probeRelay sends one request for relayProbeURL through the Gateway's /relay
// endpoint, using the same envelope the browser relay uses. It returns the
// origin status that the Gateway reports.
func probeRelay(ctx context.Context, client *http.Client, endpoint, gatewayKey string) (int, error) {
	payload, err := json.Marshal(workerRequest{
		Key:     gatewayKey,
		URL:     relayProbeURL,
		Method:  http.MethodGet,
		Headers: map[string]string{"Accept": "*/*"},
	})
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return 0, fmt.Errorf("request /relay: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxRelayJSON+1))
	if err != nil {
		return response.StatusCode, fmt.Errorf("read /relay response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, &workerHTTPError{StatusCode: response.StatusCode, Snippet: workerErrorSnippet(data)}
	}
	var envelope workerResponse
	if err := json.Unmarshal(data, &envelope); err != nil {
		return response.StatusCode, fmt.Errorf("Gateway returned a malformed envelope: %s", workerErrorSnippet(data))
	}
	if envelope.Error != "" {
		return response.StatusCode, fmt.Errorf("Gateway: %s", envelope.Error)
	}
	if envelope.Status != http.StatusOK && envelope.Status != http.StatusNoContent {
		return envelope.Status, fmt.Errorf("test request returned origin HTTP %d", envelope.Status)
	}
	return envelope.Status, nil
}

func httpStatusMeaning(code int) string {
	switch code {
	case http.StatusOK:
		return "200 OK — Gateway responded"
	case http.StatusMovedPermanently:
		return "301 Moved Permanently — Worker URL redirects permanently"
	case http.StatusFound:
		return "302 Found — Worker URL redirects"
	case http.StatusBadRequest:
		return "400 Bad Request — Gateway rejected the request"
	case http.StatusUnauthorized:
		return "401 Unauthorized — the Gateway password was rejected"
	case http.StatusForbidden:
		return "403 Forbidden — Cloudflare denied access"
	case http.StatusNotFound:
		return "404 Not Found — the Gateway /health route was not found"
	case http.StatusTooManyRequests:
		return "429 Too Many Requests — rate limited"
	case http.StatusInternalServerError:
		return "500 Internal Server Error — the Gateway failed while handling the request"
	case http.StatusBadGateway:
		return "502 Bad Gateway — the Gateway could not complete a Fetch Worker request"
	case http.StatusServiceUnavailable:
		return "503 Service Unavailable — the Gateway or Fetch Worker is not configured"
	default:
		if text := http.StatusText(code); text != "" {
			return fmt.Sprintf("%d %s", code, text)
		}
		return fmt.Sprintf("HTTP %d — unknown status", code)
	}
}

type tailStatus struct {
	Running        bool   `json:"running"`
	GatewayRunning bool   `json:"gatewayRunning"`
	FetchRunning   bool   `json:"fetchRunning"`
	GatewayWorker  string `json:"gatewayWorker"`
	FetchWorker    string `json:"fetchWorker"`
	Error          string `json:"error"`
}

type cloudflareTail struct {
	mu         sync.Mutex
	cmd        *exec.Cmd
	cancel     context.CancelFunc
	running    bool
	stopping   bool // set by Stop() so the wait goroutine can tell normal kills from crashes
	done       chan struct{} // closed when the current process has fully exited and its state is updated
	workerName string
	lastError  string
	sourceName string
	logs       *appLogBuffer
}

type cloudflareTailGroup struct {
	gateway *cloudflareTail
	fetch   *cloudflareTail
}

type startTailRequest struct {
	AccountID     string `json:"accountId"`
	GatewayWorker string `json:"gatewayWorker"`
	FetchWorker   string `json:"fetchWorker"`
	Token         string `json:"token"`
	Remember      bool   `json:"remember"`
}

var accountIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

var workerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

func newCloudflareTail(logs *appLogBuffer, sourceName string) *cloudflareTail {
	return &cloudflareTail{logs: logs, sourceName: sourceName}
}

func newCloudflareTailGroup(logs *appLogBuffer) *cloudflareTailGroup {
	return &cloudflareTailGroup{
		gateway: newCloudflareTail(logs, "Gateway"),
		fetch:   newCloudflareTail(logs, "Fetch Worker"),
	}
}

func (g *cloudflareTailGroup) Start(accountID, gatewayName, fetchName, token string) error {
	if strings.EqualFold(strings.TrimSpace(gatewayName), strings.TrimSpace(fetchName)) {
		return errors.New("Gateway and Fetch Worker names must be different")
	}
	gatewayStatus, fetchStatus := g.gateway.Status(), g.fetch.Status()
	if gatewayStatus.Running || fetchStatus.Running {
		return errors.New("one or both Worker log streams are already running; stop them before restarting")
	}
	if err := g.gateway.Start(accountID, gatewayName, token); err != nil {
		return fmt.Errorf("start Gateway log stream: %w", err)
	}
	if err := g.fetch.Start(accountID, fetchName, token); err != nil {
		g.gateway.Stop()
		return fmt.Errorf("start Fetch Worker log stream: %w", err)
	}
	return nil
}

func (g *cloudflareTailGroup) Stop() {
	g.gateway.Stop()
	g.fetch.Stop()
}

func (g *cloudflareTailGroup) Status() tailStatus {
	gatewayStatus, fetchStatus := g.gateway.Status(), g.fetch.Status()
	status := tailStatus{
		GatewayRunning: gatewayStatus.Running,
		FetchRunning:   fetchStatus.Running,
		GatewayWorker:  g.gateway.workerNameSnapshot(),
		FetchWorker:    g.fetch.workerNameSnapshot(),
		Running:        gatewayStatus.Running || fetchStatus.Running,
	}
	if gatewayStatus.Error != "" {
		status.Error = gatewayStatus.Error
	}
	if fetchStatus.Error != "" {
		if status.Error != "" {
			status.Error += "; "
		}
		status.Error += fetchStatus.Error
	}
	return status
}

func (t *cloudflareTail) workerNameSnapshot() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.workerName
}

func (t *cloudflareTail) Start(accountID, workerName, token string) error {
	accountID = strings.TrimSpace(accountID)
	workerName = strings.TrimSpace(workerName)
	token = strings.TrimSpace(token)
	if !accountIDPattern.MatchString(accountID) {
		return errors.New("enter a 32-character Cloudflare account ID")
	}
	if !workerNamePattern.MatchString(workerName) {
		return errors.New("Worker name may contain letters, numbers, hyphens, and underscores")
	}
	if token == "" {
		return errors.New("enter a Cloudflare API token with Worker tail/log access")
	}

	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return errors.New("Cloudflare log stream is already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd, err := makeWranglerTailCommand(ctx, workerName)
	if err != nil {
		cancel()
		t.mu.Unlock()
		return err
	}
	cmd.Cancel = func() error {
		_ = exec.Command("taskkill.exe", "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F").Run()
		return nil
	}
	wranglerConfig := filepath.Join(os.TempDir(), "MedoVPN", "wrangler-config")
	if err := os.MkdirAll(wranglerConfig, 0700); err != nil {
		cancel()
		t.mu.Unlock()
		return fmt.Errorf("create Wrangler config directory: %w", err)
	}
	cmd.Env = environmentWith(os.Environ(), map[string]string{
		"CLOUDFLARE_API_TOKEN":  token,
		"CLOUDFLARE_ACCOUNT_ID": accountID,
		"XDG_CONFIG_HOME":       wranglerConfig,
	}, map[string]struct{}{
		"CLIENT_AUTH_KEY":      {},
		"WORKER_TOKEN":         {},
		"RELAY_TOKEN":          {},
		"UPSTREAM_RELAY_TOKEN": {},
	})
	// Output goes through in-process pipes instead of StdoutPipe/StderrPipe.
	// cmd.Wait then waits for the process and for the copying of its output,
	// and WaitDelay bounds that second wait: if wrangler leaves a child
	// process holding the pipes open after it exits, Wait gives up after 5 s
	// and closes them, instead of the readers blocking forever.
	outR, outW := io.Pipe()
	errR, errW := io.Pipe()
	cmd.Stdout = outW
	cmd.Stderr = errW
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		cancel()
		t.mu.Unlock()
		_ = outW.Close()
		_ = errW.Close()
		return fmt.Errorf("start Wrangler tail: %w", err)
	}
	done := make(chan struct{})
	t.cmd = cmd
	t.cancel = cancel
	t.done = done
	t.running = true
	t.workerName = workerName
	t.lastError = ""
	t.stopping = false
	t.mu.Unlock()

	t.logs.add(t.sourceName, "Starting live tail for Worker "+workerName)
	var readers sync.WaitGroup
	readers.Add(2)
	go func() {
		defer readers.Done()
		t.scanOutput(t.sourceName, outR, token)
	}()
	go func() {
		defer readers.Done()
		t.scanOutput("Wrangler "+t.sourceName, errR, token)
	}()
	go func() {
		defer close(done)
		waitErr := cmd.Wait()
		// Wait has returned, so nothing writes to the pipes any more. Close
		// them so the readers reach EOF and finish.
		_ = outW.Close()
		_ = errW.Close()
		readers.Wait()
		if errors.Is(waitErr, exec.ErrWaitDelay) {
			// The process exited normally; only its output pipes lingered.
			waitErr = nil
		}
		t.mu.Lock()
		intentional := t.stopping
		if t.cmd == cmd {
			t.running = false
			t.cmd = nil
			t.cancel = nil
			t.stopping = false
			// Only record an error when the exit was unexpected.
			// A SIGKILL from Stop() gives "signal: killed", which is not
			// context.Canceled, so without the stopping flag it was wrongly
			// surfaced as an error in the UI.
			if waitErr != nil && !intentional && !errors.Is(waitErr, context.Canceled) {
				t.lastError = "Wrangler tail stopped: " + waitErr.Error()
			}
		}
		t.mu.Unlock()
		if waitErr != nil && !intentional && !errors.Is(waitErr, context.Canceled) {
			t.logs.add("Wrangler "+t.sourceName, "tail exited unexpectedly: "+waitErr.Error())
		} else {
			t.logs.add(t.sourceName, "Live Worker tail stopped")
		}
	}()
	return nil
}

// readBoundedLine reads one line from br. It keeps at most limit bytes of the
// line and discards the rest up to the newline. An oversized line therefore
// costs bounded memory, and it does not swallow the line after it. The
// returned line has no trailing newline.
func readBoundedLine(br *bufio.Reader, limit int) (line string, truncated bool, err error) {
	var buf []byte
	for {
		chunk, readErr := br.ReadSlice('\n')
		room := limit - len(buf)
		if room < 0 {
			room = 0
		}
		var discarded []byte
		if len(chunk) > room {
			discarded = chunk[room:]
			buf = append(buf, chunk[:room]...)
		} else {
			buf = append(buf, chunk...)
		}
		// Discarding the trailing newline (or CRLF) itself is not data loss;
		// only mark the line truncated when it cut off real content.
		if len(strings.TrimRight(string(discarded), "\r\n")) > 0 {
			truncated = true
		}
		if readErr == bufio.ErrBufferFull {
			continue
		}
		return strings.TrimRight(string(buf), "\r\n"), truncated, readErr
	}
}

func (t *cloudflareTail) scanOutput(source string, reader io.Reader, token string) {
	const maxLine = 1 << 20 // 1 MiB per line
	br := bufio.NewReaderSize(reader, 64<<10)
	for {
		line, truncated, err := readBoundedLine(br, maxLine)
		if truncated {
			line += " …[line truncated]"
		}
		if line != "" {
			if token != "" {
				line = strings.ReplaceAll(line, token, "[REDACTED]")
			}
			t.logs.add(source, line)
		}
		if err != nil {
			if err != io.EOF {
				t.logs.add(source, "read tail output: "+err.Error())
			}
			return
		}
	}
}

func (t *cloudflareTail) Stop() {
	t.mu.Lock()
	cancel, cmd, done := t.cancel, t.cmd, t.done
	// Set the flag only when a process is actually running. A flag left set
	// while idle would make the next genuine crash look like a normal stop.
	if cmd != nil {
		t.stopping = true
	}
	t.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		if runtime.GOOS == "windows" {
			_ = exec.Command("taskkill.exe", "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F").Run()
		} else {
			// syscall.Kill and SysProcAttr.Setpgid are Unix-only identifiers.
			// Use the portable process method here so this single-file client
			// also compiles with the Windows syscall package.
			_ = cmd.Process.Kill()
		}
	}
	if cancel != nil {
		cancel()
	}
	// Wait for the process to be fully reaped and its state updated, so a
	// caller that restarts right after Stop never sees a stale "running".
	if cmd != nil && done != nil {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	}
}

func (t *cloudflareTail) Status() tailStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return tailStatus{Running: t.running, Error: t.lastError}
}

func makeWranglerTailCommand(ctx context.Context, workerName string) (*exec.Cmd, error) {
	// Run wrangler directly. The earlier version built a cmd.exe /c command
	// line by hand, which broke when the Wrangler path contained spaces. Go
	// quotes each argument for Windows itself, and the Worker name has already
	// been checked against workerNamePattern.
	wranglerPath, err := exec.LookPath("wrangler")
	if err != nil {
		return nil, errors.New("Wrangler was not found on PATH; install Wrangler to stream Cloudflare logs")
	}
	return exec.CommandContext(ctx, wranglerPath, "tail", workerName, "--format", "json"), nil
}

func environmentWith(base []string, replacements map[string]string, omitted map[string]struct{}) []string {
	result := make([]string, 0, len(base)+len(replacements))
	// Normalize omitted keys to uppercase for consistent comparison
	omittedUpper := make(map[string]struct{}, len(omitted))
	for key := range omitted {
		omittedUpper[strings.ToUpper(key)] = struct{}{}
	}
	// Normalize replacement keys to uppercase for consistent comparison
	replacementsUpper := make(map[string]string, len(replacements))
	for key, value := range replacements {
		replacementsUpper[strings.ToUpper(key)] = value
	}

	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		key = strings.ToUpper(key)
		if _, skip := omittedUpper[key]; skip {
			continue
		}
		if _, replaced := replacementsUpper[key]; replaced {
			continue
		}
		result = append(result, entry)
	}
	for key, value := range replacementsUpper {
		result = append(result, key+"="+value)
	}
	return result
}

type appLogEntry struct {
	ID      uint64    `json:"id"`
	Time    time.Time `json:"time"`
	Source  string    `json:"source"`
	Message string    `json:"message"`
}

type appLogBuffer struct {
	mu      sync.RWMutex
	entries []appLogEntry
	nextID  uint64
	limit   int
}

type appLogWriter struct {
	buffer *appLogBuffer
}

type logsResult struct {
	Entries []appLogEntry `json:"entries"`
	NextID  uint64        `json:"nextId"`
}

func newAppLogBuffer(limit int) *appLogBuffer {
	return &appLogBuffer{limit: limit}
}

func (b *appLogBuffer) add(source, message string) {
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}
	if len(message) > maxUILogLine {
		message = message[:maxUILogLine] + " …[log line truncated]"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextID++
	b.entries = append(b.entries, appLogEntry{
		ID:      b.nextID,
		Time:    time.Now().UTC(),
		Source:  source,
		Message: message,
	})
	if len(b.entries) > b.limit {
		copy(b.entries, b.entries[len(b.entries)-b.limit:])
		b.entries = b.entries[:b.limit]
	}
}

func (b *appLogBuffer) since(after uint64) logsResult {
	b.mu.RLock()
	defer b.mu.RUnlock()
	entries := make([]appLogEntry, 0)
	for _, entry := range b.entries {
		if entry.ID > after {
			entries = append(entries, entry)
		}
	}
	return logsResult{Entries: entries, NextID: b.nextID}
}

func (w appLogWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\r\n"), "\n") {
		if line != "" {
			w.buffer.add("Go", strings.TrimSuffix(line, "\r"))
		}
	}
	return len(p), nil
}

const (
	maxUILogEntries = 500
	maxUILogLine    = 64 << 10
)

const maxUIRequestBytes = 64 << 10

type controlUI struct {
	controller          *proxyController
	uiToken             string
	allowedHost         string
	defaults            proxySettings
	initialGatewayKey   string
	gatewayKeyPath      string
	settingsFile        string
	cloudflareTokenPath string
	cloudflareToken     string
	logs                *appLogBuffer
	tail                *cloudflareTailGroup
	tokenMu             sync.Mutex
	cloudflareTokenMu   sync.Mutex
	settingsMu          sync.RWMutex
}

type startRequest struct {
	Settings   proxySettings `json:"settings"`
	GatewayKey string        `json:"gatewayKey"`
}

var controlPage = template.Must(template.New("control").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>MedoVPN</title>
  <style>
    :root { font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; color: #eaf0fa; background: #0b1220; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; background: radial-gradient(ellipse at 15% 0%, #183252 0, transparent 42%), #0b1220; }
    main { width: min(1040px, calc(100% - 32px)); margin: 0 auto; padding: 48px 0 36px; }
    header { display: flex; align-items: center; justify-content: space-between; gap: 20px; margin-bottom: 28px; }
    .brand { display: flex; align-items: center; gap: 14px; }
    .mark { display: grid; place-items: center; width: 48px; height: 48px; border: 1px solid #335273; border-radius: 15px; color: #7de4c0; background: #11273a; font-size: 24px; }
    h1 { margin: 0; font-size: 25px; letter-spacing: -.5px; }
    .subtitle { margin: 5px 0 0; color: #95a8bf; font-size: 14px; }
    .badge { display: inline-flex; align-items: center; gap: 8px; padding: 9px 12px; border: 1px solid #334357; border-radius: 999px; color: #a9b8c9; background: #111b2b; font-size: 13px; white-space: nowrap; }
    .led { width: 8px; height: 8px; border-radius: 50%; background: #8391a1; box-shadow: 0 0 12px currentColor; }
    .badge.running { border-color: #23634f; color: #83e1b9; }
    .badge.running .led { background: #4bd39a; }
    .panel { padding: 26px; border: 1px solid #27364a; border-radius: 18px; background: #111b2beF; box-shadow: 0 22px 70px #0005; }
    .panel-head { display: flex; align-items: start; justify-content: space-between; gap: 18px; margin-bottom: 22px; }
    h2 { margin: 0; font-size: 18px; }
    .hint { margin: 7px 0 0; color: #91a2b8; font-size: 13px; line-height: 1.55; }
    .fields { display: grid; grid-template-columns: 1fr 1fr; gap: 17px; }
    label { display: block; color: #b7c5d6; font-size: 12px; font-weight: 650; letter-spacing: .035em; }
    input { width: 100%; margin-top: 8px; padding: 12px 13px; border: 1px solid #34445a; border-radius: 10px; outline: none; color: #f1f5fb; background: #0b1422; font: inherit; font-size: 14px; }
    input:focus { border-color: #4ea98b; box-shadow: 0 0 0 3px #4ea98b22; }
    input:disabled { opacity: .58; }
    .wide { grid-column: 1 / -1; }
    .actions { display: flex; align-items: center; gap: 11px; margin-top: 23px; }
    button { padding: 11px 17px; border: 1px solid transparent; border-radius: 10px; cursor: pointer; font: inherit; font-size: 14px; font-weight: 700; }
    button:disabled { cursor: wait; opacity: .55; }
    .start { color: #06241c; background: #75dfb8; }
    .stop { color: #f0c8c8; border-color: #634047; background: #281a24; }
    .status-box { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 18px; padding: 15px; border: 1px solid #26364b; border-radius: 12px; background: #0c1523; }
    .status-label { display: block; margin-bottom: 5px; color: #8598af; font-size: 11px; text-transform: uppercase; letter-spacing: .08em; }
    .status-value { overflow-wrap: anywhere; color: #dce8f6; font-size: 13px; }
    #message { min-height: 20px; margin: 15px 0 0; color: #9badc2; font-size: 13px; }
    #message.error { color: #ffaaa8; }
    .note { margin: 16px 2px 0; color: #8da0b7; font-size: 12px; line-height: 1.6; }
    code { color: #c2d7ee; }
    .panel + .panel { margin-top: 18px; }
    .check-status { display: flex; align-items: center; gap: 9px; color: #a9b8c9; font-size: 14px; font-weight: 700; }
    .check-dot { width: 10px; height: 10px; border-radius: 50%; background: #8391a1; }
    .check-dot.reachable { background: #4bd39a; box-shadow: 0 0 12px #4bd39a88; }
    .check-dot.degraded { background: #ffc66d; box-shadow: 0 0 12px #ffc66d77; }
    .check-dot.offline { background: #ff7474; box-shadow: 0 0 12px #ff747477; }
    .compact-panel .panel-head { align-items: center; margin-bottom: 10px; }
    .disclosure { margin-top: 10px; overflow: hidden; border: 1px solid #26364b; border-radius: 12px; background: #0c1523; }
    .disclosure-summary { display: flex; align-items: center; justify-content: space-between; gap: 14px; padding: 12px 14px; cursor: pointer; list-style: none; color: #dce8f6; font-size: 14px; font-weight: 700; }
    .disclosure-summary::-webkit-details-marker { display: none; }
    .disclosure-summary:focus-visible { outline: 2px solid #4ea98b; outline-offset: -3px; }
    .disclosure[open] > .disclosure-summary { border-bottom: 1px solid #26364b; }
    .disclosure-arrow { flex: 0 0 auto; color: #91a2b8; font-size: 19px; line-height: 1; transition: transform .18s ease; }
    .disclosure[open] .disclosure-arrow { transform: rotate(180deg); }
    .disclosure-body { padding: 0 14px 14px; }
    .log-disclosure { margin-top: 0; border: 0; background: transparent; }
    .log-disclosure > .disclosure-summary { padding: 0 0 12px; }
    .log-disclosure[open] > .disclosure-summary { border-bottom: 1px solid #26364b; }
    .log-disclosure .disclosure-body { padding: 12px 0 0; }
    .details-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-top: 18px; }
    .detail { min-width: 0; padding: 13px; border: 1px solid #26364b; border-radius: 11px; background: #0c1523; }
    .detail pre { margin: 8px 0 0; color: #c7d6e7; font: 12px/1.55 ui-monospace, SFMono-Regular, Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
    .log-output { height: 300px; overflow: auto; margin: 14px 0 0; padding: 12px; border: 1px solid #26364b; border-radius: 11px; background: #080e18; color: #c8d6e6; font: 12px/1.55 ui-monospace, SFMono-Regular, Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
    .log-controls { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 14px; }
    .log-line { padding: 2px 0; border-bottom: 1px solid #ffffff0a; }
    .log-time { color: #7188a2; }
    .log-source { color: #78d8b2; }
    .secondary { color: #d1dfef; border-color: #34445a; background: #182438; }
    .remember { display: flex; align-items: center; gap: 8px; margin-top: 11px; color: #91a2b8; font-size: 12px; font-weight: 400; letter-spacing: 0; }
    .remember input { width: auto; margin: 0; }
    .cert-upload { grid-column: 1 / -1; }
    .cert-upload-row { display: grid; grid-template-columns: 1fr auto; align-items: end; gap: 11px; margin-top: 8px; }
    .cert-upload-row input[type=file] { margin-top: 0; }
    .cert-upload-status { margin: 8px 0 0; color: #91a2b8; font-size: 12px; line-height: 1.5; overflow-wrap: anywhere; }
    @media (max-width: 680px) { main { padding-top: 26px; } header { align-items: flex-start; } .badge { margin-top: 4px; } .panel { padding: 19px; } .fields, .status-box, .details-grid, .cert-upload-row { grid-template-columns: 1fr; } .wide { grid-column: auto; } .log-controls { align-items: flex-start; flex-direction: column; } }
    @media (max-width: 450px) { header { flex-direction: column; } }
  </style>
</head>
<body>
  <main>
    <header>
      <div class="brand"><div class="mark">↗</div><div><h1>MedoVPN</h1><p class="subtitle">Local proxy · Cloudflare Worker relay</p></div></div>
      <div id="badge" class="badge"><span class="led"></span><span id="badgeText">Proxy stopped</span></div>
    </header>
    <section class="panel">
       <div class="panel-head"><div><h2>Connection settings</h2><p class="hint">Enter the Cloudflare Worker HTTPS URL. The Go app sends relay requests directly to its /relay endpoint; it does not use an Apps Script relay.</p></div></div>
      <form id="settingsForm">
        <div class="fields">
          <label class="wide">Cloudflare Worker URL<input name="workerURL" type="url" placeholder="https://your-worker.example" value="{{.Defaults.WorkerURL}}" required></label>
          <label class="wide">Worker password<input name="gatewayKey" type="password" autocomplete="off" placeholder="{{if .HasGatewayKey}}Password already configured; leave blank to reuse it{{else}}Enter the same key configured in your Worker{{end}}"></label>
          <label>Local proxy address<input name="listenAddress" value="{{.Defaults.ListenAddress}}" placeholder="127.0.0.1:2020" required></label>
          <label>Browser inspection CA certificate path<input name="caCertPath" value="{{.Defaults.CACertPath}}" required></label>
          <label class="wide">Browser inspection CA private key path<input name="caKeyPath" value="{{.Defaults.CAKeyPath}}" required></label>
          <div class="cert-upload">
            <label for="workerCACertFile">Worker TLS CA certificate</label>
            <div class="cert-upload-row">
              <input id="workerCACertFile" type="file" accept=".crt,.cer,.pem,application/x-pem-file,application/pkix-cert">
              <button id="uploadWorkerCACertButton" class="secondary" type="button">Upload certificate</button>
            </div>
            <input id="workerCACertPath" value="{{.Defaults.WorkerCACertPath}}" placeholder="No extra Worker CA certificate uploaded" readonly>
            <p id="workerCACertStatus" class="cert-upload-status">Optional: adds a CA certificate to Go's trust roots for HTTPS connections to the Worker. It does not make an expired Worker certificate valid.</p>
          </div>
          <label>Cloudflare account ID<input name="cloudflareAccountId" value="{{.Defaults.CloudflareAccountID}}" placeholder="32-character account ID"></label>
          <label>Gateway Worker script name<input name="cloudflareWorker" value="{{.Defaults.CloudflareWorker}}" placeholder="gateway"></label>
          <label>Fetch Worker script name<input name="cloudflareFetchWorker" value="{{.Defaults.CloudflareFetchWorker}}" placeholder="fetch"></label>
        </div>

        <!-- DPI Evasion & Transport Configuration (Capabilities 1-10) -->
        <details style="margin:24px 0 0; border:1px solid #26364b; border-radius:12px; background:#0c1523; padding:16px;">
          <summary style="cursor:pointer; color:#75dfb8; font-weight:600; font-size:16px; list-style:none;">
            ⚙️ DPI Evasion & Transport Configuration (Click to expand)
            <span style="float:right; color:#91a2b8;">▼</span>
          </summary>
          <div style="margin-top:16px;">
            
            <!-- Capability 1: Hedging -->
            <div style="margin:16px 0; padding:14px; border:1px solid #26364b; border-radius:10px; background:#0b1422;">
              <label style="display:flex; align-items:center; gap:10px; color:#b7c5d6; font-size:14px; font-weight:600;">
                <input name="enableHedging" type="checkbox" {{if .Defaults.EnableHedging}}checked{{end}} style="width:auto; margin:0;">
                <span>Hedged Requests (duplicate idempotent requests)</span>
              </label>
              <p style="margin:8px 0 0; color:#7188a2; font-size:12px;">Races a second request if primary doesn't answer quickly.</p>
              <label style="display:block; margin-top:10px; color:#91a2b8; font-size:13px;">Hedge Delay (ms): <input name="hedgeDelayMs" type="number" min="500" max="10000" value="{{.Defaults.HedgeDelayMs}}" style="width:100px;"></label>
            </div>

            <!-- Capability 2: Connection Rotation -->
            <div style="margin:16px 0; padding:14px; border:1px solid #26364b; border-radius:10px; background:#0b1422;">
              <label style="display:flex; align-items:center; gap:10px; color:#b7c5d6; font-size:14px; font-weight:600;">
                <input name="enableConnectionRotation" type="checkbox" {{if .Defaults.EnableConnectionRotation}}checked{{end}} style="width:auto; margin:0;">
                <span>Connection Rotation (kill connections before DPI threshold)</span>
              </label>
              <p style="margin:8px 0 0; color:#7188a2; font-size:12px;">Closes connections before they reach DPI classification window.</p>
              <label style="display:block; margin-top:10px; color:#91a2b8; font-size:13px;">Max Age (seconds): <input name="connectionMaxAgeSec" type="number" min="5" max="300" value="{{.Defaults.ConnectionMaxAgeSec}}" style="width:100px;"></label>
            </div>

            <!-- Capability 3: Fragmentation -->
            <div style="margin:16px 0; padding:14px; border:1px solid #26364b; border-radius:10px; background:#0b1422;">
              <label style="display:flex; align-items:center; gap:10px; color:#b7c5d6; font-size:14px; font-weight:600;">
                <input name="enableFragmentation" type="checkbox" {{if .Defaults.EnableFragmentation}}checked{{end}} style="width:auto; margin:0;">
                <span>ClientHello Fragmentation (split SNI across packets)</span>
              </label>
              <p style="margin:8px 0 0; color:#7188a2; font-size:12px;">Splits first TLS handshake into multiple TCP segments.</p>
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:10px;">
                <label style="color:#91a2b8; font-size:13px;">Pieces: <input name="fragmentPieces" type="number" min="2" max="6" value="{{.Defaults.FragmentPieces}}" style="width:80px;"></label>
                <label style="color:#91a2b8; font-size:13px;">Delay (ms): <input name="fragmentDelayMs" type="number" min="0" max="50" value="{{.Defaults.FragmentDelayMs}}" style="width:80px;"></label>
                <label style="color:#91a2b8; font-size:13px;">Min size: <input name="fragmentSizeMin" type="number" min="8" max="200" value="{{.Defaults.FragmentSizeMin}}" style="width:80px;"></label>
                <label style="color:#91a2b8; font-size:13px;">Max size (fallback mode): <input name="fragmentSizeMax" type="number" min="20" max="500" value="{{.Defaults.FragmentSizeMax}}" style="width:80px;"></label>
              </div>
            </div>

            <!-- Capability 4: Retry Logic -->
            <div style="margin:16px 0; padding:14px; border:1px solid #26364b; border-radius:10px; background:#0b1422;">
              <label style="display:flex; align-items:center; gap:10px; color:#b7c5d6; font-size:14px; font-weight:600;">
                <input name="enableRetry" type="checkbox" {{if .Defaults.EnableRetry}}checked{{end}} style="width:auto; margin:0;">
                <span>Retry on Failure</span>
              </label>
              <p style="margin:8px 0 0; color:#7188a2; font-size:12px;">Automatically retry transient connection failures.</p>
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:10px;">
                <label style="color:#91a2b8; font-size:13px;">Max Attempts: <input name="maxRetryAttempts" type="number" min="1" max="10" value="{{.Defaults.MaxRetryAttempts}}" style="width:80px;"></label>
                <label style="color:#91a2b8; font-size:13px;">Strategy: 
                  <select name="retryStrategy" style="width:140px;">
                    <option value="immediate" {{if eq .Defaults.RetryStrategy "immediate"}}selected{{end}}>Immediate</option>
                    <option value="fixed" {{if eq .Defaults.RetryStrategy "fixed"}}selected{{end}}>Fixed Delay</option>
                    <option value="exponential" {{if eq .Defaults.RetryStrategy "exponential"}}selected{{end}}>Exponential</option>
                  </select>
                </label>
                <label style="color:#91a2b8; font-size:13px;">Initial (ms): <input name="initialBackoffMs" type="number" min="0" max="5000" value="{{.Defaults.InitialBackoffMs}}" style="width:80px;"></label>
                <label style="color:#91a2b8; font-size:13px;">Max (ms): <input name="maxBackoffMs" type="number" min="100" max="60000" value="{{.Defaults.MaxBackoffMs}}" style="width:80px;"></label>
                <label style="color:#91a2b8; font-size:13px;">Multiplier: <input name="backoffMultiplier" type="number" min="1" max="10" step="0.1" value="{{.Defaults.BackoffMultiplier}}" style="width:80px;"></label>
                <label style="display:flex; align-items:center; gap:8px; color:#91a2b8; font-size:13px;">
                  <input name="retryOnTimeout" type="checkbox" {{if .Defaults.RetryOnTimeout}}checked{{end}} style="width:auto; margin:0;">
                  <span>Retry timeouts</span>
                </label>
              </div>
            </div>

            <!-- Capability 5 & 6: Connection Pool -->
            <div style="margin:16px 0; padding:14px; border:1px solid #26364b; border-radius:10px; background:#0b1422;">
              <label style="display:flex; align-items:center; gap:10px; color:#b7c5d6; font-size:14px; font-weight:600;">
                <input name="enableConnectionPool" type="checkbox" {{if .Defaults.EnableConnectionPool}}checked{{end}} style="width:auto; margin:0;">
                <span>Connection Pool & Concurrency</span>
              </label>
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:12px;">
                <label style="color:#91a2b8; font-size:13px;">Max Concurrent: <input name="maxConcurrentRequests" type="number" min="0" max="100" value="{{.Defaults.MaxConcurrentRequests}}" style="width:80px;"></label>
                <label style="display:flex; align-items:center; gap:8px; color:#91a2b8; font-size:13px;">
                  <input name="enableConnectionReuse" type="checkbox" {{if .Defaults.EnableConnectionReuse}}checked{{end}} style="width:auto; margin:0;">
                  <span>Reuse Connections</span>
                </label>
                <label style="color:#91a2b8; font-size:13px;">Max Idle: <input name="maxIdleConns" type="number" min="0" max="1000" value="{{.Defaults.MaxIdleConns}}" style="width:80px;"></label>
                <label style="color:#91a2b8; font-size:13px;">Per Host: <input name="maxIdleConnsPerHost" type="number" min="0" max="100" value="{{.Defaults.MaxIdleConnsPerHost}}" style="width:80px;"></label>
                <label style="color:#91a2b8; font-size:13px;">Idle Timeout (s): <input name="idleConnTimeoutSec" type="number" min="0" max="300" value="{{.Defaults.IdleConnTimeoutSec}}" style="width:80px;"></label>
              </div>
              <p style="margin:8px 0 0; color:#7188a2; font-size:11px;">Max Concurrent 0 = unlimited. The toggle above switches the concurrency limit on or off; connection reuse is controlled by the separate "Reuse Connections" checkbox.</p>
            </div>

            <!-- Capability 7: Health Check -->
            <div style="margin:16px 0; padding:14px; border:1px solid #26364b; border-radius:10px; background:#0b1422;">
              <label style="display:flex; align-items:center; gap:10px; color:#b7c5d6; font-size:14px; font-weight:600;">
                <input name="enableHealthCheck" type="checkbox" {{if .Defaults.EnableHealthCheck}}checked{{end}} style="width:auto; margin:0;">
                <span>Dashboard health monitor</span>
              </label>
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:12px;">
                <label style="color:#91a2b8; font-size:13px;">Mode: 
                  <select name="healthCheckMode" style="width:140px;">
                    <option value="endpoint" {{if eq .Defaults.HealthCheckMode "endpoint"}}selected{{end}}>Endpoint</option>
                    <option value="disabled" {{if eq .Defaults.HealthCheckMode "disabled"}}selected{{end}}>Disabled</option>
                  </select>
                </label>
                <label style="color:#91a2b8; font-size:13px;">Interval (s): <input name="healthCheckInterval" type="number" min="10" max="600" value="{{.Defaults.HealthCheckInterval}}" style="width:80px;"></label>
                <label style="color:#91a2b8; font-size:13px;">Timeout (s): <input name="healthCheckTimeout" type="number" min="1" max="120" value="{{.Defaults.HealthCheckTimeout}}" style="width:80px;"></label>
              </div>
              <p style="margin:8px 0 0; color:#7188a2; font-size:11px;">Checks the Gateway while this page is open (the timer stops when the page is closed). Timeout applies to every check, including the Check button.</p>
            </div>

            <!-- Capability 8: CDN Edge IP Override -->
            <div style="margin:16px 0; padding:14px; border:1px solid #26364b; border-radius:10px; background:#0b1422;">
              <label style="display:block; color:#b7c5d6; font-size:14px; font-weight:600; margin-bottom:8px;">CDN Edge IP Override (optional)</label>
              <input name="cdnEdgeIP" type="text" placeholder="e.g. 104.16.123.45" value="{{.Defaults.CDNEdgeIP}}" style="width:100%;">
              <p style="margin:8px 0 0; color:#7188a2; font-size:12px;">Dial this IP while keeping original SNI/Host. Leave empty for normal DNS resolution.</p>
            </div>

            <!-- DNS over HTTPS (DoH) -->
            <div style="margin:16px 0; padding:14px; border:1px solid #26364b; border-radius:10px; background:#0b1422;">
              <label style="display:flex; align-items:center; gap:10px; color:#b7c5d6; font-size:14px; font-weight:600;">
                <input name="dohEnabled" type="checkbox" {{if .Defaults.DoHEnabled}}checked{{end}} style="width:auto; margin:0;">
                <span>🔐 DNS over HTTPS (Encrypted DNS)</span>
              </label>
              <p style="margin:8px 0 0; color:#7188a2; font-size:12px;">Encrypt DNS queries to prevent ISP monitoring and manipulation.</p>
              <label style="display:block; margin-top:10px; color:#91a2b8; font-size:13px;">
                DoH Provider: 
                <select name="dohProvider" style="width:100%; margin-top:5px;">
                  <option value="https://1.1.1.1/dns-query" {{if eq .Defaults.DoHProvider "https://1.1.1.1/dns-query"}}selected{{end}}>Cloudflare 1.1.1.1 (no filtering)</option>
                  <option value="https://8.8.8.8/dns-query" {{if eq .Defaults.DoHProvider "https://8.8.8.8/dns-query"}}selected{{end}}>Google Public DNS (no filtering)</option>
                  <option value="https://94.140.15.15/dns-query" {{if eq .Defaults.DoHProvider "https://94.140.15.15/dns-query"}}selected{{end}}>AdGuard DNS (blocks ads and trackers)</option>
                  <option value="https://94.140.15.16/dns-query" {{if eq .Defaults.DoHProvider "https://94.140.15.16/dns-query"}}selected{{end}}>AdGuard Family Protection (blocks adult content)</option>
                  <option value="https://185.222.222.222/dns-query" {{if eq .Defaults.DoHProvider "https://185.222.222.222/dns-query"}}selected{{end}}>DNS.SB (no filtering)</option>
                  {{if and (ne .Defaults.DoHProvider "") (ne .Defaults.DoHProvider "https://1.1.1.1/dns-query") (ne .Defaults.DoHProvider "https://8.8.8.8/dns-query") (ne .Defaults.DoHProvider "https://94.140.15.15/dns-query") (ne .Defaults.DoHProvider "https://94.140.15.16/dns-query") (ne .Defaults.DoHProvider "https://185.222.222.222/dns-query")}}
                  <option value="{{.Defaults.DoHProvider}}" selected>{{.Defaults.DoHProvider}} (saved)</option>
                  {{end}}
                </select>
              </label>
              <p style="margin:8px 0 0; color:#7188a2; font-size:11px;">Top providers sorted by speed.</p>
            </div>

            <!-- Capability 9: Timeouts -->
            <div style="margin:16px 0; padding:14px; border:1px solid #26364b; border-radius:10px; background:#0b1422;">
              <h3 style="margin:0 0 10px; color:#75dfb8; font-size:14px; font-weight:600;">Timeouts (milliseconds)</h3>
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                <label style="color:#91a2b8; font-size:13px;">Dial: <input name="dialTimeoutMs" type="number" min="1000" max="60000" value="{{.Defaults.DialTimeoutMs}}" style="width:90px;"></label>
                <label style="color:#91a2b8; font-size:13px;">TLS Handshake: <input name="tlsHandshakeTimeoutMs" type="number" min="1000" max="60000" value="{{.Defaults.TLSHandshakeTimeoutMs}}" style="width:90px;"></label>
                <label style="color:#91a2b8; font-size:13px;">Response Header: <input name="responseHeaderTimeoutMs" type="number" min="1000" max="120000" value="{{.Defaults.ResponseHeaderTimeoutMs}}" style="width:90px;"></label>
                <label style="color:#91a2b8; font-size:13px;">Stall Timeout: <input name="requestTimeoutMs" type="number" min="5000" max="300000" value="{{.Defaults.RequestTimeoutMs}}" style="width:90px;"></label>
              </div>
            </div>

            <!-- ALPN Configuration -->
            <div style="margin:16px 0; padding:14px; border:1px solid #26364b; border-radius:10px; background:#0b1422;">
              <label style="display:block; color:#b7c5d6; font-size:14px; font-weight:600; margin-bottom:8px;">ALPN Protocols (Advanced)</label>
              <input name="alpnProtocols" type="text" placeholder="http/1.1 (h2 disabled by design)" value="{{.Defaults.ALPNProtocols}}" style="width:100%;">
              <p style="margin:8px 0 0; color:#7188a2; font-size:12px;">Comma-separated list. Leave empty to use Go's default. HTTP/2 is disabled for Worker connections by design to prevent DPI multiplexing.</p>
            </div>

          </div>

          <!-- Save Button at End of Advanced DPI Section -->
          <button type="button" id="saveDPIButton" style="margin:20px 0 0 0; padding:10px 20px; background:#4a90e2; color:#fff; border:none; border-radius:6px; cursor:pointer; font-size:14px; font-weight:600; width:100%;">💾 Save DPI Settings</button>

        </details>

        <div class="actions"><button id="startButton" class="start" type="submit">Start proxy</button><button id="stopButton" class="stop" type="button" disabled>Stop proxy</button></div>
      </form>
      <div class="status-box">
        <div><span class="status-label">Browser proxy</span><span id="proxyStatus" class="status-value">127.0.0.1:2020</span></div>
        <div><span class="status-label">Gateway relay</span><span id="workerStatus" class="status-value">Not connected</span></div>
        <div><span class="status-label">Total Requests</span><span id="statsRequests" class="status-value">0</span></div>
        <div><span class="status-label">Success Rate</span><span id="statsSuccess" class="status-value">100%</span></div>
      </div>
      <p id="message" role="status" aria-live="polite"></p>
      <p class="note">Set your browser's HTTP and HTTPS proxy to <code id="proxyHint">127.0.0.1:2020</code>. HTTPS inspection requires the CA certificate to be trusted by the browser. The Worker password and URL are saved for the next app run.</p>
    </section>
    <section class="panel compact-panel">
      <div class="panel-head">
        <div><h2>Gateway connection</h2><p class="hint">Health and response time.</p></div>
        <button id="checkWorkerButton" class="secondary" type="button">Check</button>
      </div>
      <details id="workerDetails" class="disclosure">
        <summary class="disclosure-summary">
          <span class="check-status"><span id="workerCheckDot" class="check-dot"></span><span id="workerCheckLabel">Not checked yet</span></span>
          <span class="disclosure-arrow" aria-hidden="true">⌄</span>
        </summary>
        <div class="disclosure-body">
          <div class="details-grid">
            <div class="detail"><span class="status-label">HTTP response</span><div id="workerHTTPStatus" class="status-value">—</div><div id="workerHTTPMeaning" class="hint"></div></div>
            <div class="detail"><span class="status-label">Latency</span><div id="workerLatency" class="status-value">—</div></div>
            <div class="detail"><span class="status-label">Response body</span><pre id="workerBody">—</pre></div>
          </div>
          <p class="note"><code id="curlCommand">curl -i --max-time 10 https://your-worker.example/health</code></p>
          <p id="workerCheckError" class="note" role="status"></p>
        </div>
      </details>
    </section>
    <section class="panel">
      <details id="logDisclosure" class="disclosure log-disclosure">
        <summary class="disclosure-summary">
          <div><h2>Cloudflare Worker logs</h2><p class="hint">Expand to view live logs and controls.</p></div>
          <span class="disclosure-arrow" aria-hidden="true">⌄</span>
        </summary>
        <div class="disclosure-body">
          <div class="fields">
            <label class="wide">Cloudflare API token<input id="cloudflareAPIToken" type="password" autocomplete="off" placeholder="{{if .HasCloudflareToken}}A saved or environment token is available; leave blank to use it{{else}}Enter a token with Worker tail/log access{{end}}"></label>
          </div>
          <label class="remember"><input id="rememberCloudflareToken" type="checkbox" checked> Remember this token in this device's user config</label>
          <div class="log-controls">
            <div class="check-status"><span id="tailDot" class="check-dot"></span><span id="tailStatusText">Gateway and Fetch Worker log streams stopped</span></div>
            <div class="actions" style="margin-top:0"><button id="startTailButton" class="start" type="button">Start Cloudflare logs</button><button id="stopTailButton" class="stop" type="button" disabled>Stop logs</button></div>
          </div>
          <p class="note">Live logs require Wrangler and a token allowed to read Worker tail events. Remembered tokens are stored in this device's user config.</p>
          <div id="logOutput" class="log-output" role="log" aria-live="polite">Waiting for logs…</div>
        </div>
      </details>
    </section>
  </main>
  <script>
    "use strict";
    const uiToken = {{.UIToken}};
    const form = document.getElementById("settingsForm");
    const badge = document.getElementById("badge");
    const badgeText = document.getElementById("badgeText");
    const message = document.getElementById("message");
    const startButton = document.getElementById("startButton");
    const stopButton = document.getElementById("stopButton");
    const checkWorkerButton = document.getElementById("checkWorkerButton");
    const workerCACertFile = document.getElementById("workerCACertFile");
    const uploadWorkerCACertButton = document.getElementById("uploadWorkerCACertButton");
    const logDisclosure = document.getElementById("logDisclosure");
    const logOutput = document.getElementById("logOutput");
    const startTailButton = document.getElementById("startTailButton");
    const stopTailButton = document.getElementById("stopTailButton");
    let lastLogID = 0;
    let busy = false;
    let tailBusy = false;
    let workerCheckBusy = false;

    logDisclosure.addEventListener("toggle", () => {
      if (logDisclosure.open) logOutput.scrollTop = logOutput.scrollHeight;
    });

    function showMessage(text, isError) {
      message.textContent = text || "";
      message.classList.toggle("error", Boolean(isError));
    }

    async function api(path, options = {}) {
      const headers = new Headers(options.headers || {});
      headers.set("X-Medo-UI-Token", uiToken);
      if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
      const response = await fetch(path, { ...options, headers, cache: "no-store" });
      const text = await response.text();
      let result;
      try {
        result = JSON.parse(text);
      } catch (parseErr) {
        throw new Error("Request failed (" + response.status + "): " + text.slice(0, 120));
      }
      if (!response.ok) throw new Error(result.error || ("Request failed (" + response.status + ")"));
      return result;
    }

    function setBusy(value) {
      busy = value;
      startButton.disabled = value || stopButton.dataset.running === "true";
      stopButton.disabled = value || stopButton.dataset.running !== "true";
    }

    async function refreshStatus() {
      try {
        const state = await api("/api/status");
        const running = Boolean(state.running);
        stopButton.dataset.running = String(running);
        badge.classList.toggle("running", running);
        badgeText.textContent = running ? "Proxy running" : "Proxy stopped";
        document.getElementById("proxyStatus").textContent = state.proxyAddress || form.elements.listenAddress.value;
        document.getElementById("proxyHint").textContent = state.proxyAddress || form.elements.listenAddress.value;
        document.getElementById("workerStatus").textContent = state.workerURL || "Not connected";
        setBusy(busy);
        if (state.lastError) showMessage(state.lastError, true);
      } catch (error) {
        showMessage(error.message, true);
      }
    }

    async function refreshStats() {
      try {
        const stats = await api("/api/stats");
        document.getElementById("statsRequests").textContent = stats.totalRequests || 0;
        document.getElementById("statsSuccess").textContent = (stats.successRate ?? 100).toFixed(1) + "%";
      } catch (error) {
        // Stats endpoint failure is non-critical, don't show error
      }
    }

    // Reads every settings field from the control panel form. Shared by Start,
    // Save DPI, and Save Config so the three cannot drift apart.
    function collectSettings(data) {
      return {
        workerURL: data.get("workerURL"),
        listenAddress: data.get("listenAddress"),
        caCertPath: data.get("caCertPath"),
        caKeyPath: data.get("caKeyPath"),
        workerCACertPath: document.getElementById("workerCACertPath").value,
        cloudflareAccountId: data.get("cloudflareAccountId"),
        cloudflareWorker: data.get("cloudflareWorker"),
        cloudflareFetchWorker: data.get("cloudflareFetchWorker"),
        enableHedging: data.get("enableHedging") === "on",
        hedgeDelayMs: parseInt(data.get("hedgeDelayMs") || "8000", 10),
        enableConnectionRotation: data.get("enableConnectionRotation") === "on",
        connectionMaxAgeSec: parseInt(data.get("connectionMaxAgeSec") || "12", 10),
        enableFragmentation: data.get("enableFragmentation") === "on",
        fragmentDelayMs: parseInt(data.get("fragmentDelayMs") || "12", 10),
        fragmentPieces: parseInt(data.get("fragmentPieces") || "3", 10),
        fragmentSizeMin: parseInt(data.get("fragmentSizeMin") || "8", 10),
        fragmentSizeMax: parseInt(data.get("fragmentSizeMax") || "120", 10),
        enableRetry: data.get("enableRetry") === "on",
        maxRetryAttempts: parseInt(data.get("maxRetryAttempts") || "3", 10),
        retryStrategy: data.get("retryStrategy") || "exponential",
        initialBackoffMs: parseInt(data.get("initialBackoffMs") || "150", 10),
        maxBackoffMs: parseInt(data.get("maxBackoffMs") || "5000", 10),
        backoffMultiplier: parseFloat(data.get("backoffMultiplier") || "2.0"),
        retryOnTimeout: data.get("retryOnTimeout") === "on",
        maxConcurrentRequests: parseInt(data.get("maxConcurrentRequests") || "0", 10),
        enableConnectionPool: data.get("enableConnectionPool") === "on",
        enableConnectionReuse: data.get("enableConnectionReuse") === "on",
        maxIdleConns: parseInt(data.get("maxIdleConns") || "100", 10),
        maxIdleConnsPerHost: parseInt(data.get("maxIdleConnsPerHost") || "20", 10),
        idleConnTimeoutSec: parseInt(data.get("idleConnTimeoutSec") || "10", 10),
        cdnEdgeIP: data.get("cdnEdgeIP") || "",
        dialTimeoutMs: parseInt(data.get("dialTimeoutMs") || "15000", 10),
        tlsHandshakeTimeoutMs: parseInt(data.get("tlsHandshakeTimeoutMs") || "15000", 10),
        responseHeaderTimeoutMs: parseInt(data.get("responseHeaderTimeoutMs") || "90000", 10),
        requestTimeoutMs: parseInt(data.get("requestTimeoutMs") || "90000", 10),
        alpnProtocols: data.get("alpnProtocols") || "",
        dohEnabled: data.get("dohEnabled") === "on",
        dohProvider: data.get("dohProvider") || "",
        enableHealthCheck: data.get("enableHealthCheck") === "on",
        healthCheckMode: data.get("healthCheckMode") || "endpoint",
        healthCheckInterval: parseInt(data.get("healthCheckInterval") || "60", 10),
        healthCheckTimeout: parseInt(data.get("healthCheckTimeout") || "10", 10)
      };
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (busy) return;
      setBusy(true);
      showMessage("Starting local proxy…", false);
      const data = new FormData(form);
      const payload = {
        settings: collectSettings(data),
        gatewayKey: data.get("gatewayKey")
      };
      try {
        const result = await api("/api/start", { method: "POST", body: JSON.stringify(payload) });
        form.elements.gatewayKey.value = "";
        stopButton.dataset.running = "true";
        showMessage("Proxy started at " + result.proxyAddress + ". Configure the browser proxy to use it.", false);
        await refreshStatus();
      } catch (error) {
        showMessage(error.message, true);
      } finally {
        setBusy(false);
      }
    });

    stopButton.addEventListener("click", async () => {
      if (busy) return;
      setBusy(true);
      try {
        await api("/api/stop", { method: "POST" });
        showMessage("Local proxy stopped.", false);
        await refreshStatus();
      } catch (error) {
        showMessage(error.message, true);
      } finally {
        setBusy(false);
      }
    });

    // Save DPI Settings button
    const saveDPIButton = document.getElementById("saveDPIButton");
    if (saveDPIButton) {
      saveDPIButton.addEventListener("click", async () => {
        if (busy) return;
        setBusy(true);
        showMessage("Saving DPI settings...", false);
        const data = new FormData(form);
        const payload = { settings: collectSettings(data) };
        try {
          await api("/api/save-config", { method: "POST", body: JSON.stringify(payload) });
          if (stopButton.dataset.running === "true") {
            showMessage("Saved. Stop and start the proxy to apply.", false);
          } else {
            showMessage("✅ DPI settings saved successfully!", false);
          }
        } catch (error) {
          showMessage("❌ Failed to save: " + error.message, true);
        } finally {
          setBusy(false);
        }
      });
    }

    // Auto-save settings when DPI feature toggles are changed
    const dpiToggleNames = ["enableHedging", "enableConnectionRotation", "enableFragmentation", "enableRetry", "enableConnectionReuse", "retryOnTimeout", "dohEnabled", "enableConnectionPool", "enableHealthCheck"];
    for (const name of dpiToggleNames) {
      const checkbox = form.elements[name];
      if (checkbox) {
        checkbox.addEventListener("change", async () => {
          // Auto-save the current form state when a toggle changes
          const data = new FormData(form);
          const payload = { settings: collectSettings(data) };
          try {
            await api("/api/save-config", { method: "POST", body: JSON.stringify(payload) });
            // Silently save without notification; just log it
          } catch (error) {
            showMessage(error.message, true);
          }
        });
      }
    }

    async function checkWorker() {
      if (workerCheckBusy) return;
      const workerURL = form.elements.workerURL.value.trim();
      const checkError = document.getElementById("workerCheckError");
      if (!workerURL) {
        checkError.textContent = "Enter the Gateway Worker URL first.";
        return;
      }
      workerCheckBusy = true;
      checkWorkerButton.disabled = true;
      checkError.textContent = "Checking Gateway HTTPS health endpoint…";
      try {
        const result = await api("/api/worker-check", {
          method: "POST",
          body: JSON.stringify({
            workerURL,
            workerCACertPath: document.getElementById("workerCACertPath").value,
            gatewayKey: form.elements.gatewayKey.value,
            settings: collectSettings(new FormData(form))
          })
        });
        const dot = document.getElementById("workerCheckDot");
        dot.className = "check-dot " + (result.reachable ? "reachable" : "offline");
        document.getElementById("workerCheckLabel").textContent = result.healthy
          ? "Gateway and relay healthy"
          : !result.reachable ? "Gateway could not be reached"
          : result.relayTested ? "Gateway reachable; relay test failed"
          : "Gateway responded; enter the Worker password to test the relay";
        document.getElementById("workerHTTPStatus").textContent = result.status
          ? String(result.status)
          : "No HTTP response";
        document.getElementById("workerHTTPMeaning").textContent = result.meaning || "";
        document.getElementById("workerLatency").textContent = Number.isFinite(result.latencyMs)
          ? result.latencyMs.toFixed(1) + " ms"
          : "—";
        document.getElementById("workerBody").textContent = result.body || result.error || "(empty response)";
        checkError.textContent = result.error || "";
        try {
          const healthURL = new URL(workerURL);
          healthURL.pathname = "/health";
          healthURL.search = "";
          healthURL.hash = "";
          document.getElementById("curlCommand").textContent = "curl -i --max-time 10 " + healthURL.toString();
        } catch (_) {
          document.getElementById("curlCommand").textContent = "curl -i --max-time 10 WORKER_URL/health";
        }
      } catch (error) {
        document.getElementById("workerCheckDot").className = "check-dot offline";
        document.getElementById("workerCheckLabel").textContent = "Gateway could not be checked";
        checkError.textContent = error.message;
      } finally {
        workerCheckBusy = false;
        checkWorkerButton.disabled = false;
      }
    }

    uploadWorkerCACertButton.addEventListener("click", () => workerCACertFile.click());
    workerCACertFile.addEventListener("change", async () => {
      const file = workerCACertFile.files && workerCACertFile.files[0];
      if (!file) return;
      uploadWorkerCACertButton.disabled = true;
      const status = document.getElementById("workerCACertStatus");
      status.textContent = "Checking and saving certificate…";
      try {
        const upload = new FormData();
        upload.append("certificate", file, file.name);
        const result = await api("/api/worker-ca", { method: "POST", body: upload });
        document.getElementById("workerCACertPath").value = result.path;
        status.textContent = "Uploaded " + file.name + ". Stop and restart the proxy to apply it to relay traffic.";
        showMessage("Worker TLS CA certificate uploaded and saved.", false);
      } catch (error) {
        status.textContent = error.message;
        showMessage(error.message, true);
      } finally {
        workerCACertFile.value = "";
        uploadWorkerCACertButton.disabled = false;
      }
    });

    async function refreshTailStatus() {
      try {
        const state = await api("/api/cloudflare-logs/status");
        document.getElementById("tailDot").className = "check-dot " + (state.running ? "reachable" : "");
        const gatewayState = state.gatewayRunning ? "live" : "stopped";
        const fetchState = state.fetchRunning ? "live" : "stopped";
        document.getElementById("tailStatusText").textContent = state.running
          ? "Gateway " + (state.gatewayWorker || "") + ": " + gatewayState + " · Fetch " + (state.fetchWorker || "") + ": " + fetchState
          : (state.error || "Gateway and Fetch Worker log streams stopped");
        startTailButton.disabled = tailBusy || state.running;
        stopTailButton.disabled = tailBusy || !state.running;
      } catch (error) {
        document.getElementById("tailStatusText").textContent = error.message;
      }
    }

    async function refreshLogs() {
      try {
        const result = await api("/api/logs?after=" + encodeURIComponent(lastLogID));
        const output = document.getElementById("logOutput");
        const wasAtBottom = output.scrollHeight - output.clientHeight - output.scrollTop < 16;
        if (lastLogID === 0 && result.entries.length === 0 && output.textContent === "Waiting for logs…") {
          output.textContent = "No logs yet. Start the Worker tail or make a proxy request.";
        }
        if (result.entries.length > 0 && output.dataset.hasLogs !== "true") {
          output.replaceChildren();
          output.dataset.hasLogs = "true";
        }
        for (const entry of result.entries) {
          const line = document.createElement("div");
          line.className = "log-line";
          const stamp = document.createElement("span");
          stamp.className = "log-time";
          stamp.textContent = new Date(entry.time).toLocaleTimeString();
          const source = document.createElement("span");
          source.className = "log-source";
          source.textContent = " [" + entry.source + "] ";
          const messageText = document.createElement("span");
          messageText.textContent = entry.message;
          line.append(stamp, source, messageText);
          output.appendChild(line);
          lastLogID = Math.max(lastLogID, entry.id);
        }
        while (output.childElementCount > 500) output.removeChild(output.firstElementChild);
        if (result.nextId > lastLogID) lastLogID = result.nextId;
        if (wasAtBottom) output.scrollTop = output.scrollHeight;
      } catch (_) {}
    }

    checkWorkerButton.addEventListener("click", checkWorker);
    startTailButton.addEventListener("click", async () => {
      if (tailBusy) return;
      tailBusy = true;
      startTailButton.disabled = true;
      try {
        await api("/api/cloudflare-logs/start", {
          method: "POST",
          body: JSON.stringify({
            accountId: form.elements.cloudflareAccountId.value,
            gatewayWorker: form.elements.cloudflareWorker.value,
            fetchWorker: form.elements.cloudflareFetchWorker.value,
            token: document.getElementById("cloudflareAPIToken").value,
            remember: document.getElementById("rememberCloudflareToken").checked
          })
        });
        document.getElementById("cloudflareAPIToken").value = "";
        await refreshTailStatus();
        showMessage("Cloudflare log stream started.", false);
      } catch (error) {
        document.getElementById("tailStatusText").textContent = error.message;
        showMessage(error.message, true);
      } finally {
        tailBusy = false;
        await refreshTailStatus();
      }
    });
    stopTailButton.addEventListener("click", async () => {
      tailBusy = true;
      try {
        await api("/api/cloudflare-logs/stop", { method: "POST" });
      } catch (error) {
        showMessage(error.message, true);
      } finally {
        tailBusy = false;
        await refreshTailStatus();
      }
    });

    refreshStatus();
    checkWorker();
    refreshTailStatus();
    refreshLogs();
    refreshStats();
    window.setInterval(refreshStatus, 2500);
    window.setInterval(refreshStats, 3000);
    // Health check: re-read enableHealthCheck, healthCheckMode and
    // healthCheckInterval live from the form on every tick so toggling the
    // checkbox or changing the interval in the UI takes effect immediately
    // without a restart.
    let healthCheckTimer = null;
    function scheduleHealthCheck() {
      if (healthCheckTimer !== null) {
        clearInterval(healthCheckTimer);
        healthCheckTimer = null;
      }
      const enabledEl = form.elements["enableHealthCheck"];
      const modeEl    = form.elements["healthCheckMode"];
      const intervalEl = form.elements["healthCheckInterval"];
      const enabled  = enabledEl ? enabledEl.checked : false;
      const mode     = modeEl ? modeEl.value : "endpoint";
      const intervalSec = intervalEl ? parseInt(intervalEl.value || "60", 10) : 60;
      if (enabled && mode !== "disabled" && intervalSec > 0) {
        healthCheckTimer = window.setInterval(checkWorker, intervalSec * 1000);
      }
    }
    scheduleHealthCheck();
    // Re-schedule whenever the user changes one of the health-check form fields.
    ["enableHealthCheck", "healthCheckMode", "healthCheckInterval"].forEach(name => {
      const el = form.elements[name];
      if (el) el.addEventListener("change", scheduleHealthCheck);
    });
    window.setInterval(refreshTailStatus, 4000);
    window.setInterval(refreshLogs, 1500);
  </script>
</body>
</html>`))

func (ui *controlUI) authorized(w http.ResponseWriter, r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme != "http" || !ui.allowedOrigin(parsed.Host) {
			writeUIError(w, http.StatusForbidden, "request origin rejected")
			return false
		}
	}
	supplied := r.Header.Get("X-Medo-UI-Token")
	if subtle.ConstantTimeCompare([]byte(supplied), []byte(ui.uiToken)) != 1 {
		writeUIError(w, http.StatusUnauthorized, "control session expired; restart the app")
		return false
	}
	return true
}

// allowedOrigin reports whether an Origin host belongs to the control panel.
// The panel listens on a loopback address, and the browser may open it as
// 127.0.0.1, localhost or [::1], so all three are accepted on the same port.
func (ui *controlUI) allowedOrigin(host string) bool {
	gotHost, gotPort, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	_, wantPort, err := net.SplitHostPort(ui.allowedHost)
	if err != nil || gotPort != wantPort {
		return false
	}
	switch strings.ToLower(gotHost) {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

func (ui *controlUI) hasInitialGatewayKey() bool {
	ui.tokenMu.Lock()
	defer ui.tokenMu.Unlock()
	return ui.initialGatewayKey != ""
}

func (ui *controlUI) hasCloudflareToken() bool {
	ui.cloudflareTokenMu.Lock()
	defer ui.cloudflareTokenMu.Unlock()
	return ui.cloudflareToken != ""
}

func (ui *controlUI) currentSettings() proxySettings {
	ui.settingsMu.RLock()
	defer ui.settingsMu.RUnlock()
	return ui.defaults
}

func decodeUIJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	if r.ContentLength > maxUIRequestBytes {
		return errors.New("request is too large")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUIRequestBytes)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request must contain one JSON object")
		}
		return err
	}
	return nil
}

func writeUIJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeUIError(w http.ResponseWriter, status int, message string) {
	writeUIJSON(w, status, map[string]string{"error": message})
}
