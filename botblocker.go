package traefik_ultimate_bad_bot_blocker

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	log "github.com/discoverygarden/traefik-ultimate-bad-bot-blocker/utils"
)

type Config struct {
	IpBlocklistUrls        []string `json:"ipblocklisturls,omitempty"`
	IpAllowlistUrls        []string `json:"ipallowlisturls,omitempty"`
	UserAgentBlocklistUrls []string `json:"useragentblocklisturls,omitempty"`
	LogLevel               string   `json:"loglevel,omitempty"`
	// CacheDir persists the last good copy of every list, so a restart serves
	// the previous lists immediately instead of waiting for the downloads.
	CacheDir        string `json:"cachedir,omitempty"`
	RefreshInterval string `json:"refreshinterval,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		IpBlocklistUrls:        []string{},
		IpAllowlistUrls:        []string{},
		UserAgentBlocklistUrls: []string{},
		LogLevel:               "INFO",
		RefreshInterval:        "1h",
	}
}

type BotBlocker struct {
	next  http.Handler
	name  string
	state *listState
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if strconv.IntSize != 64 {
		return nil, fmt.Errorf("botblocker packs IPv4 ranges into int and needs a 64-bit platform")
	}
	logLevel, err := log.ParseLevel(config.LogLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to set log level: %w", err)
	}
	log.SetLevel(logLevel)

	interval, err := time.ParseDuration(config.RefreshInterval)
	if err != nil || interval < time.Minute {
		return nil, fmt.Errorf("refreshinterval must be a duration of at least 1m, got %q", config.RefreshInterval)
	}

	return &BotBlocker{
		name:  name,
		next:  next,
		state: sharedState(config, interval),
	}, nil
}

func (b *BotBlocker) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	startTime := time.Now()
	// Using an external plugin to avoid https://github.com/traefik/yaegi/issues/1697
	timer := getTimer(startTime)

	if !b.state.isReady() {
		timer()
		b.next.ServeHTTP(rw, req)
		return
	}

	remoteAddrPort, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		timer()
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if b.state.shouldBlockIP(remoteAddrPort.Addr()) {
		log.Infof("blocked request with from IP \"%v\"", remoteAddrPort.Addr())
		timer()
		http.Error(rw, "blocked", http.StatusForbidden)
		return
	}

	if blocked, badAgent := b.state.shouldBlockAgent(req.UserAgent()); blocked {
		log.Infof("blocked request with user agent \"%v\" because it contained \"%v\"", req.UserAgent(), badAgent)
		timer()
		http.Error(rw, "blocked", http.StatusForbidden)
		return
	}

	timer()
	b.next.ServeHTTP(rw, req)
}

func getTimer(startTime time.Time) func() {
	return func() {
		log.Debugf("Checked request in %v", time.Since(startTime))
	}
}
