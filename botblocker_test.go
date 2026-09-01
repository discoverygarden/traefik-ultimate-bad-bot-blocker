package traefik_ultimate_bad_bot_blocker

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
)

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalPrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestReadIps(t *testing.T) {
	f, err := os.Open("fixtures/lists/ip-blocklist")
	if err != nil {
		t.Fatal("Failed to open testfile")
	}

	expected := []netip.Prefix{
		netip.PrefixFrom(
			netip.AddrFrom4([4]byte{10, 10, 10, 2}),
			32,
		),
		netip.PrefixFrom(
			netip.AddrFrom4([4]byte{192, 168, 1, 1}),
			32,
		),
		netip.PrefixFrom(
			netip.AddrFrom4([4]byte{10, 10, 20, 0}),
			24,
		),
		netip.PrefixFrom(
			netip.AddrFrom16([16]byte{0x20, 0x01, 0xd, 0xb8, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88}),
			128,
		),
	}
	prefixes, err := readPrefixes(f)
	if !equalPrefixes(prefixes, expected) || err != nil {
		t.Fatalf("readPrefixes(f) = %v, %e; want %v, <nil>", prefixes, err, expected)
	}
}

func TestReadUserAgents(t *testing.T) {
	f, err := os.Open("fixtures/lists/useragent-blocklist")
	if err != nil {
		t.Fatal("Failed to open testfile")
	}

	expected := []string{"nintendobrowser", "claudebot"}
	userAgents, err := readUserAgents(f)
	if !equalStrings(userAgents, expected) || err != nil {
		t.Fatalf("readUserAgents(f) = %v, %e; want %v, <nil>", userAgents, err, expected)
	}
}

func TestShouldBlockIp(t *testing.T) {
	botBlocker := BotBlocker{
		prefixBlocklist: []netip.Prefix{
			netip.PrefixFrom(
				netip.AddrFrom4([4]byte{10, 10, 10, 2}),
				32,
			),
			netip.PrefixFrom(
				netip.AddrFrom4([4]byte{192, 168, 1, 1}),
				32,
			),
		},
	}
	badIp := netip.AddrFrom4([4]byte{10, 10, 10, 2})

	blocked := botBlocker.shouldBlockIp(badIp)
	if !blocked {
		t.Fatalf("botBlocker.shouldBlockIp(%v) = %t; want true", badIp, blocked)
	}
}

func TestShouldAllowIp(t *testing.T) {
	botBlocker := BotBlocker{
		prefixBlocklist: []netip.Prefix{
			netip.PrefixFrom(
				netip.AddrFrom4([4]byte{10, 10, 10, 2}),
				32,
			),
			netip.PrefixFrom(
				netip.AddrFrom4([4]byte{192, 168, 1, 1}),
				32,
			),
		},
	}
	ip := netip.AddrFrom4([4]byte{10, 10, 10, 2})

	blocked := botBlocker.shouldBlockIp(ip)
	if !blocked {
		t.Fatalf("botBlocker.shouldBlockIp(%v) = %t; want false", ip, blocked)
	}
}

func TestShouldBlockIpCidr(t *testing.T) {
	botBlocker := BotBlocker{
		prefixBlocklist: []netip.Prefix{
			netip.PrefixFrom(
				netip.AddrFrom4([4]byte{10, 10, 10, 0}),
				24,
			),
		},
	}
	badIp := netip.AddrFrom4([4]byte{10, 10, 10, 2})

	blocked := botBlocker.shouldBlockIp(badIp)
	if !blocked {
		t.Fatalf("botBlocker.shouldBlockIp(%v) = %t; want true", badIp, blocked)
	}
}

func TestShouldAllowIpCidr(t *testing.T) {
	botBlocker := BotBlocker{
		prefixBlocklist: []netip.Prefix{
			netip.PrefixFrom(
				netip.AddrFrom4([4]byte{10, 10, 10, 0}),
				24,
			),
		},
	}
	goodIp := netip.AddrFrom4([4]byte{10, 10, 20, 2})

	blocked := botBlocker.shouldBlockIp(goodIp)
	if blocked {
		t.Fatalf("botBlocker.shouldBlockIp(%v) = %t; want false", goodIp, blocked)
	}
}

func TestReadWhitelistIps(t *testing.T) {
	f, err := os.Open("fixtures/lists/ip-whitelist")
	if err != nil {
		t.Fatal("Failed to open testfile")
	}

	expected := []netip.Prefix{
		netip.PrefixFrom(
			netip.AddrFrom4([4]byte{10, 10, 20, 5}),
			32,
		),
		netip.PrefixFrom(
			netip.AddrFrom16([16]byte{0x20, 0x01, 0xd, 0xb8, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88}),
			128,
		),
	}
	prefixes, err := readPrefixes(f)
	if !equalPrefixes(prefixes, expected) || err != nil {
		t.Fatalf("readPrefixes(f) = %v, %e; want %v, <nil>", prefixes, err, expected)
	}
}

func TestIsWhitelistedIp(t *testing.T) {
	botBlocker := BotBlocker{
		prefixWhitelist: []netip.Prefix{
			netip.PrefixFrom(
				netip.AddrFrom4([4]byte{10, 10, 20, 5}),
				32,
			),
		},
	}
	goodIp := netip.AddrFrom4([4]byte{10, 10, 20, 5})

	whitelisted := botBlocker.isWhitelistedIp(goodIp)
	if !whitelisted {
		t.Fatalf("botBlocker.isWhitelistedIp(%v) = %t; want true", goodIp, whitelisted)
	}
}

func TestIsWhitelistedIpCidr(t *testing.T) {
	botBlocker := BotBlocker{
		prefixWhitelist: []netip.Prefix{
			netip.PrefixFrom(
				netip.AddrFrom4([4]byte{10, 10, 20, 0}),
				24,
			),
		},
	}
	goodIp := netip.AddrFrom4([4]byte{10, 10, 20, 5})

	whitelisted := botBlocker.isWhitelistedIp(goodIp)
	if !whitelisted {
		t.Fatalf("botBlocker.isWhitelistedIp(%v) = %t; want true", goodIp, whitelisted)
	}
}

func TestIsNotWhitelistedIp(t *testing.T) {
	botBlocker := BotBlocker{
		prefixWhitelist: []netip.Prefix{
			netip.PrefixFrom(
				netip.AddrFrom4([4]byte{10, 10, 20, 5}),
				32,
			),
		},
	}
	otherIp := netip.AddrFrom4([4]byte{10, 10, 10, 2})

	whitelisted := botBlocker.isWhitelistedIp(otherIp)
	if whitelisted {
		t.Fatalf("botBlocker.isWhitelistedIp(%v) = %t; want false", otherIp, whitelisted)
	}
}

// A whitelisted IP inside a blocked CIDR must be allowed through.
func TestWhitelistOverridesBlocklist(t *testing.T) {
	botBlocker := BotBlocker{
		prefixBlocklist: []netip.Prefix{
			netip.PrefixFrom(
				netip.AddrFrom4([4]byte{10, 10, 20, 0}),
				24,
			),
		},
		prefixWhitelist: []netip.Prefix{
			netip.PrefixFrom(
				netip.AddrFrom4([4]byte{10, 10, 20, 5}),
				32,
			),
		},
	}
	ip := netip.AddrFrom4([4]byte{10, 10, 20, 5})

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	botBlocker.next = next

	if !botBlocker.shouldBlockIp(ip) {
		t.Fatalf("botBlocker.shouldBlockIp(%v) = false; want true", ip)
	}

	req := httptest.NewRequest(http.MethodGet, "http://whoami.example.com", nil)
	req.RemoteAddr = "10.10.20.5:12345"
	recorder := httptest.NewRecorder()
	botBlocker.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("botBlocker.ServeHTTP() responded %d for whitelisted IP %v; want %d", recorder.Code, ip, http.StatusOK)
	}
}

func TestShouldBlockUserAgent(t *testing.T) {
	badAgent := "nintendobrowser"
	botBlocker := BotBlocker{
		userAgentBlockList: []string{
			badAgent,
		},
	}
	requestAgent := "Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30 (KHTML, like Gecko) NX/3.0.4.2.12 NintendoBrowser/4.3.1.11264.US"

	blocked, blockedAgent, err := botBlocker.shouldBlockAgent(requestAgent)
	if err != nil {
		t.Fatalf("botBlocker.shouldBlockAgent(%s) returned a none nil error", requestAgent)
	}
	if !blocked {
		t.Fatalf("botBlocker.shouldBlockAgent(%s) = %t; want true", requestAgent, blocked)
	}
	if blockedAgent != badAgent {
		t.Fatalf("botBlocker.shouldBlockAgent(%s) = %s; want \"\"", requestAgent, blockedAgent)
	}
}

func TestShouldAllowUserAgent(t *testing.T) {
	botBlocker := BotBlocker{
		userAgentBlockList: []string{
			"nintendobrowser",
		},
	}
	userAgent := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

	blocked, badAgent, err := botBlocker.shouldBlockAgent(userAgent)
	if err != nil {
		t.Fatalf("botBlocker.shouldBlockAgent(%s) returned a non nil error", userAgent)
	}
	if blocked {
		t.Fatalf("botBlocker.shouldBlockAgent(%s) = %t; want false", userAgent, blocked)
	}
	if badAgent != "" {
		t.Fatalf("botBlocker.shouldBlockAgent(%s) = %s; want \"\"", userAgent, badAgent)
	}
}

func TestShouldAllowUserAgentSubstring(t *testing.T) {
	botBlocker := BotBlocker{
		userAgentBlockList: []string{
			"obot",
		},
	}
	userAgent := "mozilla/5.0+(compatible; uptimerobot/2.0; http://www.uptimerobot.com/)"

	blocked, badAgent, err := botBlocker.shouldBlockAgent(userAgent)
	if err != nil {
		t.Fatalf("botBlocker.shouldBlockAgent(%s) returned a non nil error", userAgent)
	}
	if blocked {
		t.Fatalf("botBlocker.shouldBlockAgent(%s) = %t; want false", userAgent, blocked)
	}
	if badAgent != "" {
		t.Fatalf("botBlocker.shouldBlockAgent(%s) = %s; want \"\"", userAgent, badAgent)
	}
}
