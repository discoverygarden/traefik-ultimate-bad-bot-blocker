package utils

import (
	"fmt"
	"net/netip"
)

type node struct {
	children [2]*node
	isEnd    bool
}

// CIDRBlocklist implements a decision tree for fast IP blocking checks.
// It uses separate Tries for IPv4 and IPv6.
type CIDRBlocklist struct {
	v4Root *node
	v6Root *node
}

func NewCIDRBlocklist() *CIDRBlocklist {
	return &CIDRBlocklist{
		v4Root: &node{},
		v6Root: &node{},
	}
}

// Insert adds a prefix to the blocklist.
func (t *CIDRBlocklist) Insert(prefix netip.Prefix) error {
	addr := prefix.Addr()
	bits := prefix.Bits()

	var current *node
	var ipBytes []byte

	if addr.Is4() {
		current = t.v4Root
		b := addr.As4()
		ipBytes = b[:]
	} else if addr.Is6() {
		current = t.v6Root
		b := addr.As16()
		ipBytes = b[:]
	} else {
		// Should not happen with valid netip.Prefix
		return fmt.Errorf("invalid address type for prefix %v", prefix)
	}

	for i := 0; i < bits; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (ipBytes[byteIdx] >> bitIdx) & 1

		if current.children[bit] == nil {
			current.children[bit] = &node{}
		}
		current = current.children[bit]
	}
	current.isEnd = true
	return nil
}

// Contains checks if the given address is contained in any blocked prefix.
func (t *CIDRBlocklist) Contains(addr netip.Addr) bool {
	var current *node
	var ipBytes []byte
	var maxBits int

	if addr.Is4() {
		current = t.v4Root
		b := addr.As4()
		ipBytes = b[:]
		maxBits = 32
	} else if addr.Is6() {
		current = t.v6Root
		b := addr.As16()
		ipBytes = b[:]
		maxBits = 128
	} else {
		return false
	}

	for i := 0; i < maxBits; i++ {
		if current == nil {
			return false
		}
		// If we hit a node that marks the end of a blocked prefix, the address is blocked.
		if current.isEnd {
			return true
		}

		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (ipBytes[byteIdx] >> bitIdx) & 1

		current = current.children[bit]
	}
	// Check the final node if we reached the end of the address bits
	return current != nil && current.isEnd
}
