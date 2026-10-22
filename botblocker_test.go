package traefik_ultimate_bad_bot_blocker

import (
	"context"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustSet(t *testing.T, lines ...string) *ipSet {
	t.Helper()
	return buildSet([]parsedList{parseList(strings.NewReader(strings.Join(lines, "\n")))})
}

func TestParseFixture(t *testing.T) {
	file, err := os.Open("fixtures/lists/ip-blocklist")
	if err != nil {
		t.Fatal("Failed to open testfile")
	}
	defer file.Close()
	list := parseList(file)
	set := buildSet([]parsedList{list})
	for _, blocked := range []string{"10.10.10.2", "192.168.1.1", "10.10.20.0", "10.10.20.255", "2001:db8:3333:4444:5555:6666:7777:8888"} {
		if !set.contains(netip.MustParseAddr(blocked)) {
			t.Errorf("contains(%s) = false; want true", blocked)
		}
	}
	for _, allowed := range []string{"10.10.10.3", "10.10.21.0", "2001:db8:3333:4444:5555:6666:7777:8889"} {
		if set.contains(netip.MustParseAddr(allowed)) {
			t.Errorf("contains(%s) = true; want false", allowed)
		}
	}
}

func TestParseSkipsCommentsAndInvalidLines(t *testing.T) {
	list := parseList(strings.NewReader("# header\n1.2.3.4 # trailing\n\nnot-an-ip\n300.1.1.1\n5.6.7.0/24\n"))
	if list.invalid != 2 {
		t.Fatalf("invalid = %d; want 2", list.invalid)
	}
	set := buildSet([]parsedList{list})
	if !set.contains(netip.MustParseAddr("1.2.3.4")) || !set.contains(netip.MustParseAddr("5.6.7.200")) {
		t.Fatal("valid entries next to invalid ones were not loaded")
	}
}

func TestMappedAndEdgeRanges(t *testing.T) {
	set := mustSet(t, "::ffff:9.9.9.0/120", "0.0.0.0/0")
	if !set.contains(netip.MustParseAddr("255.255.255.255")) || !set.contains(netip.MustParseAddr("0.0.0.0")) {
		t.Fatal("0.0.0.0/0 does not cover the IPv4 space")
	}
	if set.contains(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("an IPv4 range matched an IPv6 address")
	}
	if !set.contains(netip.MustParseAddr("::ffff:8.8.8.8")) {
		t.Fatal("an IPv4-mapped address is not matched against IPv4 ranges")
	}
	v6 := mustSet(t, "::/0")
	if !v6.contains(netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")) {
		t.Fatal("::/0 does not cover the top of the IPv6 space")
	}
}

func TestMergeKeepsNestedAndAdjacentRanges(t *testing.T) {
	set := mustSet(t, "10.0.0.0/8", "10.1.0.0/16", "11.0.0.0/8", "12.0.0.5", "2001:db8::/32", "2001:db8:1::/48", "2001:db9::/32")
	if len(set.v4Starts) != 2 || len(set.v6) != 1 {
		t.Fatalf("merged into v4=%d v6=%d ranges; want 2 and 1", len(set.v4Starts), len(set.v6))
	}
	if !set.contains(netip.MustParseAddr("11.255.255.255")) || set.contains(netip.MustParseAddr("12.0.0.4")) {
		t.Fatal("merged ranges have the wrong bounds")
	}
}

// TestSetMatchesNaivePrefixScan compares the merged binary-search set with the
// original linear netip.Prefix scan over random prefixes and addresses.
func TestSetMatchesNaivePrefixScan(t *testing.T) {
	random := rand.New(rand.NewSource(42))
	randomAddr := func(v6 bool) netip.Addr {
		if v6 {
			var bytes [16]byte
			random.Read(bytes[:])
			bytes[0], bytes[1] = 0x20, 0x01
			return netip.AddrFrom16(bytes)
		}
		var bytes [4]byte
		random.Read(bytes[:])
		bytes[0] = byte(random.Intn(4)) + 10
		return netip.AddrFrom4(bytes)
	}
	for round := 0; round < 20; round++ {
		lines := make([]string, 0, 400)
		prefixes := make([]netip.Prefix, 0, 400)
		for i := 0; i < 400; i++ {
			v6 := random.Intn(4) == 0
			addr := randomAddr(v6)
			bits := 8 + random.Intn(25)
			if v6 {
				bits = 16 + random.Intn(113)
			}
			prefix := netip.PrefixFrom(addr, bits).Masked()
			prefixes = append(prefixes, prefix)
			lines = append(lines, prefix.String())
		}
		set := mustSet(t, lines...)
		for probe := 0; probe < 5000; probe++ {
			addr := randomAddr(random.Intn(4) == 0)
			if probe%3 == 0 {
				addr = prefixes[random.Intn(len(prefixes))].Addr()
			}
			want := false
			for _, prefix := range prefixes {
				if prefix.Contains(addr) {
					want = true
					break
				}
			}
			if got := set.contains(addr); got != want {
				t.Fatalf("round %d: contains(%s) = %t; naive scan says %t", round, addr, got, want)
			}
		}
	}
}

func TestUserAgentRules(t *testing.T) {
	state := &listState{ready: true, userAgents: parseUserAgents(strings.NewReader("NintendoBrowser\nobot\n"))}
	cases := []struct {
		agent string
		want  bool
	}{
		{"Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30 (KHTML, like Gecko) NX/3.0.4.2.12 NintendoBrowser/4.3.1.11264.US", true},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", false},
		{"mozilla/5.0+(compatible; uptimerobot/2.0; http://www.uptimerobot.com/)", false},
	}
	for _, testCase := range cases {
		if got, _ := state.shouldBlockAgent(testCase.agent); got != testCase.want {
			t.Errorf("shouldBlockAgent(%q) = %t; want %t", testCase.agent, got, testCase.want)
		}
	}
}

func TestAllowlistWins(t *testing.T) {
	state := &listState{
		ready:     true,
		blocklist: mustSet(t, "10.10.10.0/24"),
		allowlist: mustSet(t, "10.10.10.0/25"),
	}
	if state.shouldBlockIP(netip.MustParseAddr("10.10.10.2")) {
		t.Fatal("an allowlisted address was blocked")
	}
	if !state.shouldBlockIP(netip.MustParseAddr("10.10.10.200")) {
		t.Fatal("a blocklisted address outside the allowlist was not blocked")
	}
}

type feedServer struct {
	mutex sync.Mutex
	body  string
	fail  bool
	hits  int
}

func (f *feedServer) ServeHTTP(rw http.ResponseWriter, _ *http.Request) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.hits++
	if f.fail {
		http.Error(rw, "down", http.StatusBadGateway)
		return
	}
	_, _ = rw.Write([]byte(f.body))
}

func waitReady(t *testing.T, state *listState) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !state.isReady() {
		if time.Now().After(deadline) {
			t.Fatal("lists never became ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSharedStateAndFailedRefreshKeepsLastGood(t *testing.T) {
	feed := &feedServer{body: "203.0.113.7\n"}
	server := httptest.NewServer(feed)
	defer server.Close()

	config := CreateConfig()
	config.IpBlocklistUrls = []string{server.URL + "/shared"}
	config.CacheDir = t.TempDir()

	first, err := New(context.Background(), http.NotFoundHandler(), config, "a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(context.Background(), http.NotFoundHandler(), config, "b")
	if err != nil {
		t.Fatal(err)
	}
	state := first.(*BotBlocker).state
	if state != second.(*BotBlocker).state {
		t.Fatal("two instances with the same config did not share their lists")
	}
	waitReady(t, state)
	feed.mutex.Lock()
	hits := feed.hits
	feed.mutex.Unlock()
	if hits != 1 {
		t.Fatalf("feed fetched %d times for two instances; want 1", hits)
	}

	feed.mutex.Lock()
	feed.fail = true
	feed.mutex.Unlock()
	state.refresh()
	if !state.shouldBlockIP(netip.MustParseAddr("203.0.113.7")) {
		t.Fatal("a failed refresh dropped the last good list")
	}
}

func TestCacheServesListsWithoutNetwork(t *testing.T) {
	feed := &feedServer{body: "198.51.100.9\n"}
	server := httptest.NewServer(feed)
	cacheDir := t.TempDir()

	config := CreateConfig()
	config.IpBlocklistUrls = []string{server.URL + "/cached"}
	config.CacheDir = cacheDir
	handler, err := New(context.Background(), http.NotFoundHandler(), config, "warm")
	if err != nil {
		t.Fatal(err)
	}
	waitReady(t, handler.(*BotBlocker).state)
	server.Close()

	statesMutex.Lock()
	states = map[string]*listState{}
	statesMutex.Unlock()

	restarted, err := New(context.Background(), http.NotFoundHandler(), config, "restarted")
	if err != nil {
		t.Fatal(err)
	}
	state := restarted.(*BotBlocker).state
	if !state.isReady() {
		t.Fatal("lists were not loaded synchronously from the cache")
	}
	if !state.shouldBlockIP(netip.MustParseAddr("198.51.100.9")) {
		t.Fatal("the cached list was not applied")
	}
}

func TestNewSucceedsWhenFeedsAreUnreachableAndFailsOpen(t *testing.T) {
	config := CreateConfig()
	config.IpBlocklistUrls = []string{"http://127.0.0.1:1/unreachable"}
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusTeapot) })
	handler, err := New(context.Background(), next, config, "offline")
	if err != nil {
		t.Fatalf("New failed because a feed was unreachable: %v", err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "203.0.113.1:1234"
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusTeapot {
		t.Fatalf("status = %d before any list loaded; want the request passed through", recorder.Code)
	}
}

func TestServeHTTPBlocks(t *testing.T) {
	feed := &feedServer{body: "192.0.2.10\n"}
	agents := &feedServer{body: "badbot\n"}
	ipServer := httptest.NewServer(feed)
	defer ipServer.Close()
	agentServer := httptest.NewServer(agents)
	defer agentServer.Close()

	config := CreateConfig()
	config.IpBlocklistUrls = []string{ipServer.URL + "/serve"}
	config.UserAgentBlocklistUrls = []string{agentServer.URL + "/serve"}
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })
	handler, err := New(context.Background(), next, config, "serve")
	if err != nil {
		t.Fatal(err)
	}
	waitReady(t, handler.(*BotBlocker).state)

	cases := []struct {
		remote string
		agent  string
		want   int
	}{
		{"192.0.2.10:5000", "Mozilla/5.0", http.StatusForbidden},
		{"192.0.2.11:5000", "Mozilla/5.0 (compatible; BadBot/1.0)", http.StatusForbidden},
		{"192.0.2.11:5000", "Mozilla/5.0", http.StatusOK},
	}
	for _, testCase := range cases {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.RemoteAddr = testCase.remote
		request.Header.Set("User-Agent", testCase.agent)
		handler.ServeHTTP(recorder, request)
		if recorder.Code != testCase.want {
			t.Errorf("%s %q -> %d; want %d", testCase.remote, testCase.agent, recorder.Code, testCase.want)
		}
	}
}

func equalSets(a *ipSet, b *ipSet) bool {
	if len(a.v4Starts) != len(b.v4Starts) || len(a.v6) != len(b.v6) {
		return false
	}
	for i := range a.v4Starts {
		if a.v4Starts[i] != b.v4Starts[i] || a.v4Ends[i] != b.v4Ends[i] {
			return false
		}
	}
	for i := range a.v6 {
		if a.v6[i] != b.v6[i] {
			return false
		}
	}
	return true
}

func TestSnapshotRoundTripAndRejectsDamage(t *testing.T) {
	blocklist := mustSet(t, "1.2.3.0/24", "9.9.9.9", "0.0.0.0/8", "2001:db8::/32", "::ffff:5.5.5.5")
	allowlist := mustSet(t, "1.2.3.4", "2001:db8::1")
	path := t.TempDir() + "/snapshot.bin"
	if err := writeSnapshot(path, blocklist, allowlist); err != nil {
		t.Fatal(err)
	}
	gotBlock, gotAllow, err := readSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSets(blocklist, gotBlock) || !equalSets(allowlist, gotAllow) {
		t.Fatal("snapshot round trip changed the sets")
	}

	body, _ := os.ReadFile(path)
	damaged := map[string][]byte{
		"truncated":      body[:len(body)-3],
		"trailing bytes": append(append([]byte{}, body...), 0),
		"wrong magic":    append([]byte{0, 0, 0, 0}, body[4:]...),
	}
	unsorted := append([]byte{}, body...)
	copy(unsorted[20:24], []byte{0xff, 0xff, 0xff, 0xff})
	damaged["unsorted"] = unsorted
	for name, content := range damaged {
		damagedPath := t.TempDir() + "/snapshot.bin"
		_ = os.WriteFile(damagedPath, content, 0o644)
		if _, _, err := readSnapshot(damagedPath); err == nil {
			t.Errorf("%s snapshot was accepted", name)
		}
	}
}

func TestMissingSnapshotRebuildsFromCachedFeeds(t *testing.T) {
	feed := &feedServer{body: "192.0.2.99\n"}
	server := httptest.NewServer(feed)
	config := CreateConfig()
	config.IpBlocklistUrls = []string{server.URL + "/rebuild"}
	config.CacheDir = t.TempDir()
	handler, err := New(context.Background(), http.NotFoundHandler(), config, "first")
	if err != nil {
		t.Fatal(err)
	}
	state := handler.(*BotBlocker).state
	waitReady(t, state)
	server.Close()
	if err := os.Remove(state.snapshotPath()); err != nil {
		t.Fatalf("no snapshot was written: %v", err)
	}

	statesMutex.Lock()
	states = map[string]*listState{}
	statesMutex.Unlock()
	restarted, err := New(context.Background(), http.NotFoundHandler(), config, "second")
	if err != nil {
		t.Fatal(err)
	}
	restartedState := restarted.(*BotBlocker).state
	if !restartedState.isReady() || !restartedState.shouldBlockIP(netip.MustParseAddr("192.0.2.99")) {
		t.Fatal("lists were not rebuilt from the cached feed files")
	}
}

func TestRejectsTooShortRefreshInterval(t *testing.T) {
	config := CreateConfig()
	config.RefreshInterval = "5s"
	if _, err := New(context.Background(), http.NotFoundHandler(), config, "bad"); err == nil {
		t.Fatal("a 5s refresh interval was accepted")
	}
}
