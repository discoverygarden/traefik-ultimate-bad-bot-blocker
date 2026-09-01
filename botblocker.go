package traefik_ultimate_bad_bot_blocker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
	"sync"

	"net/http"
	"net/netip"

	"strings"
	"time"

	log "github.com/discoverygarden/traefik-ultimate-bad-bot-blocker/utils"
)

type Config struct {
	IpBlocklistUrls        []string `json:"ipblocklisturls,omitempty"`
	IpAllowlistUrls        []string `json:"ipallowlisturls,omitempty"`
	UserAgentBlocklistUrls []string `json:"useragentblocklisturls,omitempty"`
	LogLevel               string   `json:"loglevel,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		IpBlocklistUrls:        []string{},
		IpAllowlistUrls:        []string{},
		UserAgentBlocklistUrls: []string{},
		LogLevel:               "INFO",
	}
}

type BotBlocker struct {
	next               http.Handler
	name               string
	prefixBlocklist    []netip.Prefix
	userAgentBlockList []string
	prefixAllowlist    []netip.Prefix
	prefixMutex        sync.RWMutex
	uaMutex            sync.RWMutex
	Config
}

func (b *BotBlocker) update() error {
	startTime := time.Now()

	err := b.updateIps()
	if err != nil {
		return fmt.Errorf("failed to update CIDR lists: %w", err)
	}

	err = b.updateUserAgents()
	if err != nil {
		return fmt.Errorf("failed to update user agent blocklists: %w", err)
	}

	duration := time.Since(startTime)
	log.Info(
		"Updated lists.",
		"Blocked CIDRs:", len(b.prefixBlocklist),
		"Allowed CIDRs:", len(b.prefixAllowlist),
		"Blocked Agents:", len(b.userAgentBlockList),
		"Duration:", duration,
	)
	return nil
}

func (b *BotBlocker) updateIps() error {
	log.Info("Updating CIDR blocklist")
	prefixBlockList, err := fetchPrefixes(b.IpBlocklistUrls)
	if err != nil {
		return fmt.Errorf("failed to update CIDR blocklists: %w", err)
	}

	log.Info("Updating CIDR allowlist")
	prefixAllowList, err := fetchPrefixes(b.IpAllowlistUrls)
	if err != nil {
		return fmt.Errorf("failed to update CIDR allowlists: %w", err)
	}

	b.prefixMutex.Lock()
	b.prefixBlocklist = prefixBlockList
	b.prefixAllowlist = prefixAllowList
	b.prefixMutex.Unlock()
	return nil
}
func fetchPrefixes(urls []string) ([]netip.Prefix, error) {
	prefixList := make([]netip.Prefix, 0)

	for _, url := range urls {
		resp, err := http.Get(url)
		if err != nil {
			return nil, fmt.Errorf("failed fetch CIDR list: %w", err)
		}
		if resp.StatusCode > 299 {
			return nil, fmt.Errorf("failed to fetch CIDR list: received a %v from %v", resp.Status, url)
		}

		prefixes, err := readPrefixes(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to update CIDRs: %e", err)
		}
		prefixList = append(prefixList, prefixes...)
	}

	return prefixList, nil
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

	b.uaMutex.Lock()
	b.userAgentBlockList = userAgentBlockList
	b.uaMutex.Unlock()

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

	go blocker.UpdateLoop(ctx)

	return &blocker, nil
}

func (b *BotBlocker) UpdateLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			log.Info("Context stopped; stopping update loop.")
			return

		case <-time.After(time.Hour):
			log.Debug("Update loop time elapsed; updating lists.")
			break
		}
		err := b.update()
		if err != nil {
			log.Errorf("failed to update blocklist: %v", err)
		}
	}
}

func (b *BotBlocker) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	startTime := time.Now()
	log.Debugf("Checking request: CIDR: \"%v\" user agent: \"%s\"", req.RemoteAddr, req.UserAgent())
	// Using an external plugin to avoid https://github.com/traefik/yaegi/issues/1697
	timer := getTimer(startTime)

	remoteAddrPort, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		timer()
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if b.shouldBlockIp(remoteAddrPort.Addr()) {
		log.Infof("blocked request with from IP \"%v\"", remoteAddrPort.Addr())
		timer()
		http.Error(rw, "blocked", http.StatusForbidden)
		return
	}

	agent := strings.ToLower(req.UserAgent())
	blocked, badAgent, err := b.shouldBlockAgent(agent)
	if err != nil {
		timer()
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if blocked {
		log.Infof("blocked request with user agent \"%v\" because it contained \"%v\"", agent, badAgent)
		timer()
		http.Error(rw, "blocked", http.StatusForbidden)
		return
	}

	timer()
	b.next.ServeHTTP(rw, req)
}

func (b *BotBlocker) shouldBlockIp(addr netip.Addr) bool {
	b.prefixMutex.RLock()
	defer b.prefixMutex.RUnlock()

	for _, goodPrefix := range b.prefixAllowlist {
		if goodPrefix.Contains(addr) {
			return false
		}
	}
	for _, badPrefix := range b.prefixBlocklist {
		if badPrefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (b *BotBlocker) shouldBlockAgent(userAgent string) (bool, string, error) {
	userAgent = strings.ToLower(strings.TrimSpace(userAgent))
	b.uaMutex.RLock()
	defer b.uaMutex.RUnlock()
	for _, badAgent := range b.userAgentBlockList {
		// fast check with contains
		if strings.Contains(userAgent, badAgent) {
			// verify with regex
			pattern := fmt.Sprintf(`(?:\b)%s(?:\b)`, badAgent)
			matched, err := regexp.Match(pattern, []byte(userAgent))
			if err != nil {
				return false, "", fmt.Errorf("failed to check user agent %s: %e", userAgent, err)
			}
			if matched {
				return true, badAgent, nil
			}
		}
	}
	return false, "", nil
}

func getTimer(startTime time.Time) func() {
	return func() {
		log.Debugf("Checked request in %v", time.Since(startTime))
	}
}
