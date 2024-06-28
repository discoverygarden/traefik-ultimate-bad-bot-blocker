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
	ipBlocklist        []netip.Addr
	userAgentBlockList []string
	lastUpdated        time.Time
	Config
}

func (b *BotBlocker) update() error {
	startTime := time.Now()
	err := b.updateIps()
	if err != nil {
		return fmt.Errorf("failed to update IP blocklists: %w", err)
	}
	err = b.updateUserAgents()
	if err != nil {
		return fmt.Errorf("failed to update IP blocklists: %w", err)
	}

	b.lastUpdated = time.Now()
	duration := time.Now().Sub(startTime)
	log.Info("Updated block lists. Blocked IPs: ", len(b.ipBlocklist), " Duration: ", duration)
	return nil
}

func (b *BotBlocker) updateIps() error {
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

		ips, err := readIps(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to update IPs: %e", err)
		}
		ipBlockList = append(ipBlockList, ips...)
	}

	b.ipBlocklist = ipBlockList

	return nil
}

func readIps(ipReader io.ReadCloser) ([]netip.Addr, error) {
	ips := make([]netip.Addr, 0)
	defer ipReader.Close()
	scanner := bufio.NewScanner(ipReader)
	for scanner.Scan() {
		addrStr := strings.TrimSpace(scanner.Text())
		addr, err := netip.ParseAddr(addrStr)
		if err != nil {
			return []netip.Addr{}, err
		}
		ips = append(ips, addr)
	}

	return ips, nil
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
	if time.Now().Sub(b.lastUpdated) > time.Duration(time.Hour) {
		err := b.update()
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
	if b.shouldBlockIp(remoteAddrPort.Addr()) {
		log.Infof("blocked request with from IP %v", remoteAddrPort.Addr())
		log.Debugf("Checked request in %v", time.Now().Sub(startTime))
		http.Error(rw, "blocked", http.StatusForbidden)
		return
	}

	agent := strings.ToLower(req.UserAgent())
	if b.shouldBlockAgent(agent) {
		log.Infof("blocked request with user agent %v because it contained %v", agent, agent)
		log.Debugf("Checked request in %v", time.Now().Sub(startTime))
		http.Error(rw, "blocked", http.StatusForbidden)
		return
	}

	log.Debugf("Checked request in %v", time.Now().Sub(startTime))
	b.next.ServeHTTP(rw, req)
}

func (b *BotBlocker) shouldBlockIp(addr netip.Addr) bool {
	for _, badIp := range b.ipBlocklist {
		if addr == badIp {
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
