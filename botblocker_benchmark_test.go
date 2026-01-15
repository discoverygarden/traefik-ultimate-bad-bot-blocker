package traefik_ultimate_bad_bot_blocker

import (
	"fmt"
	"math/rand"
	"net/netip"
	"testing"

	"github.com/discoverygarden/traefik-ultimate-bad-bot-blocker/utils"
)

var (
	benchmarkBlocker *BotBlocker
	initDone         bool
)

func initBenchmarkBlocker() {
	if initDone {
		return
	}
	// Mimic 2.7M IPs and 200k CIDRs
	// scaling down 10x for speed of setup in tests, but it will still show O(N) slowness
	// 270k IPs, 20k CIDRs.

	prefixes := make([]netip.Prefix, 0, 300000)

	// CIDRs (approx 20k)
	for i := 0; i < 20000; i++ {
		addr := netip.AddrFrom4([4]byte{byte(rand.Intn(220) + 1), byte(rand.Intn(255)), byte(rand.Intn(255)), 0})
		prefix := netip.PrefixFrom(addr, 24)
		prefixes = append(prefixes, prefix)
	}

	// Single IPs (approx 270k)
	for i := 0; i < 270000; i++ {
		addr := netip.AddrFrom4([4]byte{byte(rand.Intn(220) + 1), byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255))})
		prefix := netip.PrefixFrom(addr, 32)
		prefixes = append(prefixes, prefix)
	}

	// Use manual initialization instead of relying on createTestBlocker from another test file
	// just to be safe and explicit in benchmarks, and avoid test-file dependency issues if run separately.
	ips := make(map[netip.Addr]struct{})
	cidrs := utils.NewCIDRBlocklist()
	for _, p := range prefixes {
		if p.IsSingleIP() {
			ips[p.Addr()] = struct{}{}
		} else {
			if err := cidrs.Insert(p); err != nil {
				panic(err)
			}
		}
	}

	benchmarkBlocker = &BotBlocker{
		blockedIPs:   ips,
		blockedCIDRs: cidrs,
	}
	initDone = true
	fmt.Printf("Benchmark setup: %d total prefixes loaded (%d IPs, %d CIDRs)\n", len(prefixes), len(ips), 20000)
}

func BenchmarkShouldBlockIp(b *testing.B) {
	initBenchmarkBlocker()
	b.ResetTimer()

	// Test with a random IP that likely isn't in the list (mostly miss) to force full scan
	// or average scan
	target := netip.AddrFrom4([4]byte{1, 2, 3, 4})

	for i := 0; i < b.N; i++ {
		benchmarkBlocker.shouldBlockIp(target)
	}
}
