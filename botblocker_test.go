package traefik_ultimate_bad_bot_blocker

import (
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

func TestShouldBlockUserAgent(t *testing.T) {
	botBlocker := BotBlocker{
		userAgentBlockList: []string{
			"nintendobrowser",
		},
	}
	badUserAgent := "Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30 (KHTML, like Gecko) NX/3.0.4.2.12 NintendoBrowser/4.3.1.11264.US"

	blocked := botBlocker.shouldBlockAgent(badUserAgent)
	if !blocked {
		t.Fatalf("botBlocker.shouldBlockAgent(%s) = %t; want true", badUserAgent, blocked)
	}
}

func TestShouldAlowUserAgent(t *testing.T) {
	botBlocker := BotBlocker{
		userAgentBlockList: []string{
			"nintendobrowser",
		},
	}
	userAgent := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

	blocked := botBlocker.shouldBlockAgent(userAgent)
	if blocked {
		t.Fatalf("botBlocker.shouldBlockAgent(%s) = %t; want false", userAgent, blocked)
	}
}
