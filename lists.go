package traefik_ultimate_bad_bot_blocker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	log "github.com/discoverygarden/traefik-ultimate-bad-bot-blocker/utils"
)

const maxListBytes = 64 * 1024 * 1024

// userAgentRule keeps the original two-step match: a cheap substring test,
// then a word-boundary regex compiled once per load instead of per request.
type userAgentRule struct {
	agent   string
	pattern *regexp.Regexp
}

// listState is shared by every middleware instance with the same config.
// Traefik builds one instance per router and rebuilds them all on every
// configuration change, so per-instance state meant one full download and
// parse per router per reload, which kept routing offline for minutes.
type listState struct {
	key        string
	config     Config
	cacheDir   string
	interval   time.Duration
	httpClient *http.Client

	mutex      sync.RWMutex
	ready      bool
	blocklist  *ipSet
	allowlist  *ipSet
	userAgents []userAgentRule

	// Last good body per URL, so one failing feed keeps its previous content
	// while the others refresh.
	lastGood map[string][]byte
}

var (
	statesMutex sync.Mutex
	states      = map[string]*listState{}
)

func stateKey(config *Config, interval time.Duration) string {
	return strings.Join([]string{
		strings.Join(config.IpBlocklistUrls, "\n"),
		strings.Join(config.IpAllowlistUrls, "\n"),
		strings.Join(config.UserAgentBlocklistUrls, "\n"),
		config.CacheDir,
		interval.String(),
	}, "\x00")
}

// sharedState returns the state for this config, creating it on first use.
// Creation loads the on-disk snapshot synchronously (milliseconds), then refreshes
// from the network in the background; it never fails on a network error.
func sharedState(config *Config, interval time.Duration) *listState {
	key := stateKey(config, interval)
	statesMutex.Lock()
	defer statesMutex.Unlock()
	if state, ok := states[key]; ok {
		return state
	}

	state := &listState{
		key:        key,
		config:     *config,
		cacheDir:   config.CacheDir,
		interval:   interval,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		lastGood:   map[string][]byte{},
	}
	state.loadCache()
	states[key] = state

	go state.refreshLoop()
	return state
}

func (s *listState) allURLs() []string {
	urls := make([]string, 0, len(s.config.IpBlocklistUrls)+len(s.config.IpAllowlistUrls)+len(s.config.UserAgentBlocklistUrls))
	urls = append(urls, s.config.IpBlocklistUrls...)
	urls = append(urls, s.config.IpAllowlistUrls...)
	urls = append(urls, s.config.UserAgentBlocklistUrls...)
	return urls
}

func cacheFileName(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:]) + ".list"
}

// loadCache restores the last good lists from the cache directory so requests
// are filtered from the first one; the background refresh then replaces them.
func (s *listState) loadCache() {
	if s.cacheDir == "" {
		return
	}
	for _, url := range s.allURLs() {
		body, err := os.ReadFile(filepath.Join(s.cacheDir, cacheFileName(url)))
		if err == nil {
			s.lastGood[url] = body
		}
	}
	if len(s.lastGood) == 0 {
		log.Warningf("no cached lists in %q; requests pass unfiltered until the first download completes", s.cacheDir)
		return
	}
	startTime := time.Now()
	if blocklist, allowlist, err := readSnapshot(s.snapshotPath()); err == nil {
		userAgents := s.parseAllUserAgents()
		s.mutex.Lock()
		s.blocklist = blocklist
		s.allowlist = allowlist
		s.userAgents = userAgents
		s.ready = true
		s.mutex.Unlock()
		log.Infof("Loaded snapshot in %v: %d blocked ranges, %d allowed ranges, %d blocked agents",
			time.Since(startTime), blocklist.size(), allowlist.size(), len(userAgents))
		return
	} else if !os.IsNotExist(err) {
		log.Warningf("ignoring unreadable snapshot %s: %v", s.snapshotPath(), err)
	}
	s.rebuild()
	log.Infof("Rebuilt lists from cached feeds in %v", time.Since(startTime))
}

func (s *listState) snapshotPath() string {
	sum := sha256.Sum256([]byte(s.key))
	return filepath.Join(s.cacheDir, "snapshot-"+hex.EncodeToString(sum[:8])+".bin")
}

func (s *listState) parseAllUserAgents() []userAgentRule {
	userAgents := make([]userAgentRule, 0)
	for _, url := range s.config.UserAgentBlocklistUrls {
		if body, ok := s.lastGood[url]; ok {
			userAgents = append(userAgents, parseUserAgents(bytes.NewReader(body))...)
		}
	}
	return userAgents
}

func (s *listState) writeCache(url string, body []byte) {
	if s.cacheDir == "" {
		return
	}
	if err := os.MkdirAll(s.cacheDir, 0o755); err != nil {
		log.Errorf("failed to create cache dir %s: %v", s.cacheDir, err)
		return
	}
	target := filepath.Join(s.cacheDir, cacheFileName(url))
	temporary := target + ".tmp"
	if err := os.WriteFile(temporary, body, 0o644); err != nil {
		log.Errorf("failed to write cache for %s: %v", url, err)
		return
	}
	if err := os.Rename(temporary, target); err != nil {
		log.Errorf("failed to replace cache for %s: %v", url, err)
	}
}

func (s *listState) fetch(url string) ([]byte, error) {
	response, err := s.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode > 299 {
		return nil, fmt.Errorf("received %v", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxListBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxListBytes {
		return nil, fmt.Errorf("list larger than %d bytes", maxListBytes)
	}
	return body, nil
}

// refresh downloads every URL. A failed or empty download keeps that URL's
// last good copy, so a feed outage never empties the lists.
func (s *listState) refresh() {
	startTime := time.Now()
	failures := 0
	for _, url := range s.allURLs() {
		body, err := s.fetch(url)
		if err == nil && len(bytes.TrimSpace(body)) == 0 {
			err = fmt.Errorf("empty response")
		}
		if err != nil {
			failures++
			log.Errorf("failed to fetch %s, keeping the last good copy: %v", url, err)
			continue
		}
		s.lastGood[url] = body
		s.writeCache(url, body)
	}
	s.rebuild()
	log.Infof("Refreshed lists in %v (%d failed feeds)", time.Since(startTime), failures)
}

func (s *listState) rebuild() {
	blocklists := make([]parsedList, 0, len(s.config.IpBlocklistUrls))
	invalid := 0
	for _, url := range s.config.IpBlocklistUrls {
		if body, ok := s.lastGood[url]; ok {
			list := parseList(bytes.NewReader(body))
			invalid += list.invalid
			blocklists = append(blocklists, list)
		}
	}
	allowlists := make([]parsedList, 0, len(s.config.IpAllowlistUrls))
	for _, url := range s.config.IpAllowlistUrls {
		if body, ok := s.lastGood[url]; ok {
			list := parseList(bytes.NewReader(body))
			invalid += list.invalid
			allowlists = append(allowlists, list)
		}
	}
	userAgents := s.parseAllUserAgents()
	blocklist := buildSet(blocklists)
	allowlist := buildSet(allowlists)

	s.mutex.Lock()
	s.blocklist = blocklist
	s.allowlist = allowlist
	s.userAgents = userAgents
	s.ready = true
	s.mutex.Unlock()

	if s.cacheDir != "" {
		if err := writeSnapshot(s.snapshotPath(), blocklist, allowlist); err != nil {
			log.Errorf("failed to write snapshot: %v", err)
		}
	}

	log.Infof(
		"Lists active. Blocked ranges: %d Allowed ranges: %d Blocked agents: %d Invalid entries skipped: %d",
		blocklist.size(), allowlist.size(), len(userAgents), invalid,
	)
}

func parseUserAgents(reader io.Reader) []userAgentRule {
	rules := make([]userAgentRule, 0)
	body, err := io.ReadAll(reader)
	if err != nil {
		return rules
	}
	for _, line := range strings.Split(string(body), "\n") {
		agent := strings.ToLower(strings.TrimSpace(line))
		if agent == "" {
			continue
		}
		pattern, err := regexp.Compile(fmt.Sprintf(`(?:\b)%s(?:\b)`, agent))
		if err != nil {
			log.Warningf("skipping user agent %q: %v", agent, err)
			continue
		}
		rules = append(rules, userAgentRule{agent: agent, pattern: pattern})
	}
	return rules
}

func (s *listState) refreshLoop() {
	s.refresh()
	for {
		time.Sleep(s.interval)
		s.refresh()
	}
}

func (s *listState) isReady() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.ready
}

func (s *listState) shouldBlockIP(addr netip.Addr) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if s.allowlist.contains(addr) {
		return false
	}
	return s.blocklist.contains(addr)
}

func (s *listState) shouldBlockAgent(userAgent string) (bool, string) {
	userAgent = strings.ToLower(strings.TrimSpace(userAgent))
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	for _, rule := range s.userAgents {
		if strings.Contains(userAgent, rule.agent) && rule.pattern.MatchString(userAgent) {
			return true, rule.agent
		}
	}
	return false, ""
}
