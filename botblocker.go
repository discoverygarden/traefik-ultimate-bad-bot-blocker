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

	"github.com/discoverygarden/traefik-ultimate-bad-bot-blocker/utils"
	log "github.com/discoverygarden/traefik-ultimate-bad-bot-blocker/utils/log"
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
	blockedIPs         map[netip.Addr]struct{}
	blockedCIDRs       *utils.CIDRBlocklist
	userAgentBlockList []string
	prefixMutex        sync.RWMutex
	uaMutex            sync.RWMutex
	Config
}

func (b *BotBlocker) update() error {
	startTime := time.Now()
	cidrCount, ipCount, err := b.updateIps()
	if err != nil {
		return fmt.Errorf("failed to update CIDR blocklists: %w", err)
	}
	err = b.updateUserAgents()
	if err != nil {
		return fmt.Errorf("failed to update user agent blocklists: %w", err)
	}

	duration := time.Since(startTime)
	log.Info("Updated block lists. Blocked IPs: ", ipCount, " Blocked CIDRs: ", cidrCount, " Duration: ", duration)
	return nil
}

func (b *BotBlocker) updateIps() (int, int, error) {
	prefixList := make([]netip.Prefix, 0)

	log.Info("Updating CIDR blocklist")
	for _, url := range b.IpBlocklistUrls {
		resp, err := http.Get(url)
		if err != nil {
			return 0, 0, fmt.Errorf("failed fetch CIDR list: %w", err)
		}
		if resp.StatusCode > 299 {
			resp.Body.Close()
			return 0, 0, fmt.Errorf("failed to fetch CIDR list: received a %v from %v", resp.Status, url)
		}

		prefixes, err := readPrefixes(resp.Body)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to update CIDRs: %w", err)
		}
		prefixList = append(prefixList, prefixes...)
	}

	newBlockedIPs := make(map[netip.Addr]struct{})
	newBlockedCIDRs := utils.NewCIDRBlocklist()

	ipCount := 0
	cidrCount := 0
	for _, p := range prefixList {
		if p.IsSingleIP() {
			newBlockedIPs[p.Addr()] = struct{}{}
			ipCount++
		} else {
			if err := newBlockedCIDRs.Insert(p); err != nil {
				log.Errorf("failed to insert CIDR %v: %v", p, err)
				continue
			}
			cidrCount++
		}
	}

	b.prefixMutex.Lock()
	b.blockedIPs = newBlockedIPs
	b.blockedCIDRs = newBlockedCIDRs
	b.prefixMutex.Unlock()

	return cidrCount, ipCount, nil
}

func readPrefixes(prefixReader io.ReadCloser) ([]netip.Prefix, error) {
	defer prefixReader.Close()

	scanner := bufio.NewScanner(prefixReader)

	// Channels for batches
	batchSize := 1000
	batches := make(chan []string, 16)
	results := make(chan []netip.Prefix, 16)
	var wg sync.WaitGroup

	// Start workers
	workers := 4 // Sweet spot often around CPU count
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for batch := range batches {
				localPrefixes := make([]netip.Prefix, 0, len(batch))
				for _, line := range batch {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}

					if strings.Contains(line, "/") {
						prefix, err := netip.ParsePrefix(line)
						if err == nil {
							localPrefixes = append(localPrefixes, prefix)
						}
					} else {
						addr, err := netip.ParseAddr(line)
						if err == nil {
							prefix := netip.PrefixFrom(addr, addr.BitLen())
							localPrefixes = append(localPrefixes, prefix)
						}
					}
				}
				results <- localPrefixes
			}
		}()
	}

	// Result collector
	done := make(chan []netip.Prefix)
	go func() {
		list := make([]netip.Prefix, 0, 4096)
		for batchResult := range results {
			list = append(list, batchResult...)
		}
		done <- list
	}()

	// Feeder
	currentBatch := make([]string, 0, batchSize)
	for scanner.Scan() {
		text := scanner.Text() // Allocate string here, sadly necessary for netip
		currentBatch = append(currentBatch, text)
		if len(currentBatch) >= batchSize {
			batches <- currentBatch
			currentBatch = make([]string, 0, batchSize)
		}
	}
	// Check for scanner error but proceed to clean up and close channels
	scanErr := scanner.Err()

	if len(currentBatch) > 0 {
		batches <- currentBatch
	}
	close(batches)
	wg.Wait()
	close(results)

	prefixes := <-done
	if scanErr != nil {
		return nil, scanErr
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

	// Fast path: check single IP map
	if _, ok := b.blockedIPs[addr]; ok {
		return true
	}

	// Slow path: check CIDR trie
	if b.blockedCIDRs != nil && b.blockedCIDRs.Contains(addr) {
		return true
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
