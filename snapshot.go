package traefik_ultimate_bad_bot_blocker

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
)

// The snapshot holds the merged block and allow sets as flat big-endian
// uint32 arrays. encoding/binary decodes each array in one compiled call, so
// a restart is ready in milliseconds instead of re-parsing and sorting every
// feed inside the plugin interpreter.
const snapshotMagic = uint32(0x42425331) // "BBS1"

func writeSnapshot(path string, blocklist *ipSet, allowlist *ipSet) error {
	temporary := path + ".tmp"
	file, err := os.Create(temporary)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(file)
	header := []uint32{
		snapshotMagic,
		uint32(len(blocklist.v4Starts)), uint32(len(blocklist.v6)),
		uint32(len(allowlist.v4Starts)), uint32(len(allowlist.v6)),
	}
	parts := []interface{}{
		header,
		blocklist.v4Starts, blocklist.v4Ends, encodeV6(blocklist.v6),
		allowlist.v4Starts, allowlist.v4Ends, encodeV6(allowlist.v6),
	}
	for _, part := range parts {
		if err = binary.Write(writer, binary.BigEndian, part); err != nil {
			break
		}
	}
	if err == nil {
		err = writer.Flush()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return os.Rename(temporary, path)
}

func readSnapshot(path string) (*ipSet, *ipSet, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	reader := bufio.NewReader(file)

	header := make([]uint32, 5)
	if err := binary.Read(reader, binary.BigEndian, header); err != nil {
		return nil, nil, err
	}
	if header[0] != snapshotMagic {
		return nil, nil, errors.New("not a botblocker snapshot")
	}
	blocklist, err := readSet(reader, header[1], header[2])
	if err != nil {
		return nil, nil, err
	}
	allowlist, err := readSet(reader, header[3], header[4])
	if err != nil {
		return nil, nil, err
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		return nil, nil, errors.New("trailing data in snapshot")
	}
	return blocklist, allowlist, nil
}

func readSet(reader io.Reader, v4Count uint32, v6Count uint32) (*ipSet, error) {
	set := &ipSet{
		v4Starts: make([]uint32, v4Count),
		v4Ends:   make([]uint32, v4Count),
	}
	if err := binary.Read(reader, binary.BigEndian, set.v4Starts); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, set.v4Ends); err != nil {
		return nil, err
	}
	for i := range set.v4Starts {
		if set.v4Starts[i] > set.v4Ends[i] || (i > 0 && set.v4Starts[i] <= set.v4Ends[i-1]) {
			return nil, errors.New("snapshot ranges are not sorted")
		}
	}
	encoded := make([]byte, int(v6Count)*32)
	if _, err := io.ReadFull(reader, encoded); err != nil {
		return nil, err
	}
	set.v6 = decodeV6(encoded)
	return set, nil
}

func encodeV6(ranges []v6Range) []byte {
	encoded := make([]byte, 0, len(ranges)*32)
	for _, current := range ranges {
		start := current.start.As16()
		end := current.end.As16()
		encoded = append(encoded, start[:]...)
		encoded = append(encoded, end[:]...)
	}
	return encoded
}

func decodeV6(encoded []byte) []v6Range {
	ranges := make([]v6Range, 0, len(encoded)/32)
	for offset := 0; offset+32 <= len(encoded); offset += 32 {
		var start, end [16]byte
		copy(start[:], encoded[offset:offset+16])
		copy(end[:], encoded[offset+16:offset+32])
		ranges = append(ranges, v6Range{start: netip.AddrFrom16(start), end: netip.AddrFrom16(end)})
	}
	return ranges
}
