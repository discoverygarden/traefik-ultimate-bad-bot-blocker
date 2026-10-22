package traefik_ultimate_bad_bot_blocker

import (
	"bufio"
	"io"
	"net/netip"
	"sort"
	"strings"
)

type v6Range struct {
	start netip.Addr
	end   netip.Addr
}

// ipSet is a sorted, non-overlapping set of address ranges. Lookups are a
// binary search, so cost does not grow with the size of the feeds. IPv4 bounds
// are kept as two flat []uint32 so a snapshot can be decoded by encoding/binary
// in compiled code rather than element by element in the plugin interpreter.
type ipSet struct {
	v4Starts []uint32
	v4Ends   []uint32
	v6       []v6Range
}

func (s *ipSet) size() int {
	if s == nil {
		return 0
	}
	return len(s.v4Starts) + len(s.v6)
}

func (s *ipSet) contains(addr netip.Addr) bool {
	if s == nil {
		return false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		value := v4Value(addr)
		index := sort.Search(len(s.v4Ends), func(i int) bool { return s.v4Ends[i] >= value })
		return index < len(s.v4Ends) && s.v4Starts[index] <= value
	}
	index := sort.Search(len(s.v6), func(i int) bool { return s.v6[i].end.Compare(addr) >= 0 })
	return index < len(s.v6) && s.v6[index].start.Compare(addr) <= 0
}

func v4Value(addr netip.Addr) uint32 {
	bytes := addr.As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}

func v6Last(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Masked().Addr().As16()
	bits := prefix.Bits()
	for i := 0; i < 16; i++ {
		bitsInByte := bits - i*8
		switch {
		case bitsInByte <= 0:
			bytes[i] = 0xff
		case bitsInByte < 8:
			bytes[i] |= byte(0xff >> bitsInByte)
		}
	}
	return netip.AddrFrom16(bytes)
}

// packV4 encodes a range as one int whose natural order is the order of the
// range starts (sign bit flipped), so sort.Ints can sort ranges in compiled
// code instead of calling an interpreted comparison 200k*log(200k) times.
func packV4(start uint32, end uint32) int {
	return int((uint64(start)<<32 | uint64(end)) ^ (1 << 63))
}

func unpackV4(packed int) (uint32, uint32) {
	value := uint64(packed) ^ (1 << 63)
	return uint32(value >> 32), uint32(value)
}

// parsedList is one feed after parsing, before it is merged with the others.
type parsedList struct {
	v4      []int
	v6      []v6Range
	invalid int
}

// parseList reads one address or CIDR per line. Blank lines and `#` comments
// are skipped; malformed entries are counted rather than failing the feed.
func parseList(reader io.Reader) parsedList {
	list := parsedList{}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		entry := strings.TrimSpace(scanner.Text())
		if comment := strings.IndexByte(entry, '#'); comment >= 0 {
			entry = strings.TrimSpace(entry[:comment])
		}
		if entry == "" {
			continue
		}
		var prefix netip.Prefix
		var err error
		if strings.Contains(entry, "/") {
			prefix, err = netip.ParsePrefix(entry)
		} else {
			var addr netip.Addr
			addr, err = netip.ParseAddr(entry)
			if err == nil {
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
		}
		if err != nil {
			list.invalid++
			continue
		}
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefix = prefix.Masked()
		if prefix.Addr().Is4() {
			start := v4Value(prefix.Addr())
			hostBits := 32 - prefix.Bits()
			end := uint32(0xffffffff)
			if hostBits < 32 {
				end = start | (uint32(1)<<hostBits - 1)
			}
			list.v4 = append(list.v4, packV4(start, end))
		} else {
			list.v6 = append(list.v6, v6Range{start: prefix.Addr(), end: v6Last(prefix)})
		}
	}
	return list
}

func buildSet(lists []parsedList) *ipSet {
	v4Count, v6Count := 0, 0
	for _, list := range lists {
		v4Count += len(list.v4)
		v6Count += len(list.v6)
	}
	v4 := make([]int, 0, v4Count)
	v6 := make([]v6Range, 0, v6Count)
	for _, list := range lists {
		v4 = append(v4, list.v4...)
		v6 = append(v6, list.v6...)
	}

	sort.Ints(v4)
	starts := make([]uint32, 0, len(v4))
	ends := make([]uint32, 0, len(v4))
	for _, packed := range v4 {
		start, end := unpackV4(packed)
		last := len(starts) - 1
		if last >= 0 && (ends[last] == 0xffffffff || start <= ends[last]+1) {
			if end > ends[last] {
				ends[last] = end
			}
			continue
		}
		starts = append(starts, start)
		ends = append(ends, end)
	}

	sort.Slice(v6, func(i, j int) bool { return v6[i].start.Less(v6[j].start) })
	mergedV6 := make([]v6Range, 0, len(v6))
	for _, current := range v6 {
		last := len(mergedV6) - 1
		if last >= 0 && adjacentOrOverlapping(mergedV6[last].end, current.start) {
			if current.end.Compare(mergedV6[last].end) > 0 {
				mergedV6[last].end = current.end
			}
			continue
		}
		mergedV6 = append(mergedV6, current)
	}

	return &ipSet{v4Starts: starts, v4Ends: ends, v6: mergedV6}
}

func adjacentOrOverlapping(previousEnd netip.Addr, nextStart netip.Addr) bool {
	following := previousEnd.Next()
	if !following.IsValid() {
		return true
	}
	return nextStart.Compare(following) <= 0
}
