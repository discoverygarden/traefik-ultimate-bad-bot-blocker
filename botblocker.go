package traefik_ultimate_bad_bot_blocker

import (
	"bufio"
	"context"
	"fmt"
	"io"

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
		IpBlocklistUrls:        []string{},
		UserAgentBlocklistUrls: []string{},
		LogLevel:               "INFO",
	}
}

type BotBlocker struct {
	next               http.Handler
	name               string
	prefixBlocklist    []netip.Prefix
	userAgentBlockList []string
	lastUpdated        time.Time
	Config
}

func (b *BotBlocker) update() error {
	startTime := time.Now()
	err := b.updateIps()
	if err != nil {
		return fmt.Errorf("failed to update CIDR blocklists: %w", err)
	}
	err = b.updateUserAgents()
	if err != nil {
		return fmt.Errorf("failed to update user agent blocklists: %w", err)
	}

	b.lastUpdated = time.Now()
	duration := time.Since(startTime)
	log.Info("Updated block lists. Blocked CIDRs: ", len(b.prefixBlocklist), " Duration: ", duration)
	return nil
}

func (b *BotBlocker) updateIps() error {
	prefixBlockList := make([]netip.Prefix, 0)

	log.Info("Updating CIDR blocklist")
	for _, url := range b.IpBlocklistUrls {
		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("failed fetch CIDR list: %w", err)
		}
		if resp.StatusCode > 299 {
			return fmt.Errorf("failed to fetch CIDR list: received a %v from %v", resp.Status, url)
		}

		prefixes, err := readPrefixes(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to update CIDRs: %e", err)
		}
		prefixBlockList = append(prefixBlockList, prefixes...)
	}

	b.prefixBlocklist = prefixBlockList

	return nil
}

func readPrefixes(prefixReader io.ReadCloser) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0)
	defer prefixReader.Close()
	scanner := bufio.NewScanner(prefixReader)
	for scanner.Scan() {
		entry := strings.TrimSpace(scanner.Text())
		var prefix netip.Prefix
		if strings.Contains(entry, "/") {
			var err error
			prefix, err = netip.ParsePrefix(entry)
			if err != nil {
				return []netip.Prefix{}, err
			}
		} else {
			addr, err := netip.ParseAddr(entry)
			if err != nil {
				return []netip.Prefix{}, err
			}
			var bits int
			if addr.Is4() {
				bits = 32
			} else {
				bits = 128
			}
			prefix, err = addr.Prefix(bits)
			if err != nil {
				return []netip.Prefix{}, err
			}
		}
		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}

func readUserAgents(userAgentReader io.ReadCloser) ([]string, error) {
	userAgents := make([]string, 0)

	defer userAgentReader.Close()
	scanner := bufio.NewScanner(userAgentReader)
	for scanner.Scan() {
		agent := strings.ToLower(strings.TrimSpace(scanner.Text()))
		userAgents = append(userAgents, agent)
	}

	return userAgents, nil
}

func (b *BotBlocker) updateUserAgents() error {
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

		agents, err := readUserAgents(resp.Body)
		if err != nil {
			return err
		}
		userAgentBlockList = append(userAgentBlockList, agents...)
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
	err = blocker.update()
	if err != nil {
		return nil, fmt.Errorf("failed to update blocklists: %s", err)
	}
	return &blocker, nil
}

func (b *BotBlocker) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if time.Since(b.lastUpdated) > time.Hour {
		err := b.update()
		if err != nil {
			log.Errorf("failed to update blocklist: %v", err)
		}
	}
	startTime := time.Now()
	log.Debugf("Checking request: CIDR: \"%v\" user agent: \"%s\"", req.RemoteAddr, req.UserAgent())
	// Using an external plugin to avoid https://github.com/traefik/yaegi/issues/1697
	timer := getTimer(startTime)
	defer timer()

	remoteAddrPort, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if b.shouldBlockIp(remoteAddrPort.Addr()) {
		log.Infof("blocked request with from IP %v", remoteAddrPort.Addr())
		http.Error(rw, "blocked", http.StatusForbidden)
		return
	}

	agent := strings.ToLower(req.UserAgent())
	if b.shouldBlockAgent(agent) {
		log.Infof("blocked request with user agent %v because it contained %v", agent, agent)
		http.Error(rw, "blocked", http.StatusForbidden)
		return
	}

	b.next.ServeHTTP(rw, req)
}

func (b *BotBlocker) shouldBlockIp(addr netip.Addr) bool {
	for _, badPrefix := range b.prefixBlocklist {
		if badPrefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (b *BotBlocker) shouldBlockAgent(userAgent string) bool {
	userAgent = strings.ToLower(strings.TrimSpace(userAgent))
	for _, badAgent := range b.userAgentBlockList {
		if strings.Contains(userAgent, badAgent) {
			return true
		}
	}
	return false
}

func getTimer(startTime time.Time) func() {
	return func() {
		log.Debugf("Checked request in %v", time.Since(startTime))
	}
}
