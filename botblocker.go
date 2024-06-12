package traefik_ultimate_bad_bot_blocker

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"time"
)

type Config struct {
	IpBlocklistUrls []string `json:"ipblocklisturls,omitempty"`
	LogLevel        string   `json:"loglevel,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		IpBlocklistUrls: []string{},
		LogLevel:        "INFO",
	}
}

type BotBlocker struct {
	next        http.Handler
	name        string
	ipBlocklist []netip.Addr
	Config
	logger *slog.Logger
}

func (b *BotBlocker) Update() error {
	ipBlockList := make([]netip.Addr, 0)

	b.logger.Info("Updating blocklists")
	startTime := time.Now()
	for _, url := range b.IpBlocklistUrls {
		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("failed fetch IP list: %w", err)
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

	duration := time.Now().Sub(startTime)
	b.logger.Info("Updated block lists", "blocked ips", len(b.ipBlocklist), "duration", duration)
	return nil
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	logLevel := slog.Level(0)
	err := logLevel.UnmarshalText([]byte(config.LogLevel))
	if err != nil {
		return nil, fmt.Errorf("failed to set log level: %w", err)
	}
	logger := slog.New(
		slog.NewTextHandler(
			os.Stdout,
			&slog.HandlerOptions{Level: logLevel},
		),
	)

	blocker := BotBlocker{
		name:   name,
		next:   next,
		Config: *config,
		logger: logger,
	}
	err = blocker.Update()
	if err != nil {
		return nil, fmt.Errorf("failed to update blocklists: %s", err)
	}
	return &blocker, nil
}

func (b *BotBlocker) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	startTime := time.Now()
	b.logger.Debug("Checking request", "IP", req.RemoteAddr)

	remoteAddrPort, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}

	if slices.Contains(b.ipBlocklist, remoteAddrPort.Addr()) {
		b.logger.Debug(fmt.Sprintf("Checked request in %v", time.Now().Sub(startTime)))
		http.Error(rw, "blocked", http.StatusForbidden)
		return
	}

	b.logger.Debug(fmt.Sprintf("Checked request in %v", time.Now().Sub(startTime)))
	b.next.ServeHTTP(rw, req)
}
