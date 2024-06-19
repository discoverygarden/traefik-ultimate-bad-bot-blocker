package traefik_ultimate_bad_bot_blocker

import (
	"bufio"
	"context"
	"fmt"

	"net/http"
	"net/netip"

	"strings"
	"time"

	log "github.com/discoverygarden/traefik-ultimate-bad-bot-blocker/utils"
)

type Config struct {
	IpBlocklistUrls        []string `json:"ipblocklisturls,omitempty"`
	UserAgentBlocklistUrls []string `json:"useragentblocklisturls,omitempty"`
	LogLevel               string   `json:"loglevel,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		IpBlocklistUrls: []string{},
		LogLevel:        "INFO",
	}
}

type BotBlocker struct {
	next               http.Handler
	name               string
	ipBlocklist        []netip.Addr
	userAgentBlockList []string
	lastUpdated        time.Time
	Config
}

func (b *BotBlocker) Update() error {
	startTime := time.Now()
	err := b.UpdateIps()
	if err != nil {
		return fmt.Errorf("failed to update IP blocklists: %w", err)
	}
	err = b.UpdateUserAgents()
	if err != nil {
		return fmt.Errorf("failed to update IP blocklists: %w", err)
	}

	b.lastUpdated = time.Now()
	duration := time.Now().Sub(startTime)
	log.Info("Updated block lists. Blocked IPs: ", len(b.ipBlocklist), " Duration: ", duration)
	return nil
}

func (b *BotBlocker) UpdateIps() error {
	ipBlockList := make([]netip.Addr, 0)

	log.Info("Updating IP blocklist")
	for _, url := range b.IpBlocklistUrls {
		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("failed fetch IP list: %w", err)
		}
		if resp.StatusCode > 299 {
			return fmt.Errorf("failed fetch IP list: received a %v from %v", resp.Status, url)
		}

		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			addrStr := scanner.Text()
			addr, err := netip.ParseAddr(addrStr)
			if err != nil {
				return fmt.Errorf("failed to parse IP address: %w", err)
			}
			ipBlockList = append(ipBlockList, addr)
		}
	}

	b.ipBlocklist = ipBlockList

	return nil
}

func (b *BotBlocker) UpdateUserAgents() error {
	userAgentBlockList := make([]string, 0)

	log.Info("Updating user agent blocklist")
	for _, url := range b.UserAgentBlocklistUrls {
		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("failed fetch useragent list: %w", err)
		}
		if resp.StatusCode > 299 {
			return fmt.Errorf("failed fetch useragent list: received a %v from %v", resp.Status, url)
		}

		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			agent := strings.ToLower(strings.TrimSpace(scanner.Text()))
			userAgentBlockList = append(userAgentBlockList, agent)
		}
	}

	b.userAgentBlockList = userAgentBlockList

	return nil
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	logLevel, err := log.ParseLevel(config.LogLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to set log level: %w", err)
	}
	log.Default().Level = logLevel

	blocker := BotBlocker{
		name:   name,
		next:   next,
		Config: *config,
	}
	err = blocker.Update()
	if err != nil {
		return nil, fmt.Errorf("failed to update blocklists: %s", err)
	}
	return &blocker, nil
}

func (b *BotBlocker) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if time.Now().Sub(b.lastUpdated) > time.Duration(time.Hour) {
		err := b.Update()
		if err != nil {
			log.Errorf("failed to update blocklist: %v", err)
		}
	}
	startTime := time.Now()
	log.Debugf("Checking request: IP: \"%v\" user agent: \"%s\"", req.RemoteAddr, req.UserAgent())

	remoteAddrPort, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	remoteAddr := remoteAddrPort.Addr()

	for _, badIP := range b.ipBlocklist {
		if remoteAddr == badIP {
			log.Infof("blocked request with from IP %v", remoteAddrPort.Addr())
			log.Debugf("Checked request in %v", time.Now().Sub(startTime))
			http.Error(rw, "blocked", http.StatusForbidden)
			return
		}
	}

	agent := strings.ToLower(req.UserAgent())
	for _, badAgent := range b.userAgentBlockList {
		if strings.Contains(agent, badAgent) {
			log.Infof("blocked request with user agent %v because it contained %v", agent, badAgent)
			log.Debugf("Checked request in %v", time.Now().Sub(startTime))
			http.Error(rw, "blocked", http.StatusForbidden)
			return
		}
	}

	log.Debugf("Checked request in %v", time.Now().Sub(startTime))
	b.next.ServeHTTP(rw, req)
}
