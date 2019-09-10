// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack_test

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

const (
	addr1     = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	addr2     = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	linkAddr1 = "\x01\x02\x03\x04\x05\x06"
	linkAddr2 = "\x01\x02\x03\x04\x05\x07"
)

// TestDADDisabled tests that an address successfully resolves immediately
// when DAD is not enabled (the default for an empty stack.Options).
func TestDADDisabled(t *testing.T) {
	opts := stack.Options{}

	e := channel.New(10, 1280, linkAddr1)
	s := stack.New([]string{ipv6.ProtocolName}, []string{icmp.ProtocolName6}, opts)
	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(_) = %s", err)
	}

	if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
		t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
	}

	// Should get the address immediately since we should not have performed
	// DAD on it.
	if addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber); err != nil || addr.Address != addr1 {
		t.Fatalf("stack.GetMainNICAddress(_, _) = %s, %s", addr, err)
	}

	// We should not have sent any NDP NS messages.
	if got := s.Stats().ICMP.V6PacketsSent.NeighborSolicit.Value(); got != 0 {
		t.Fatalf("got NeighborSolicit = %d, want = 0")
	}
}

// TestDAD tests that an address successfully resolves after performing DAD for
// various values of DupAddrDetecTransmits and RetransTimer. Included in the
// subtests is a test to make sure that invalid RetransTimer (<0.5s) values get
// fixed to the default RetransTimer of 1s.
func TestDAD(t *testing.T) {
	tests := []struct {
		name                   string
		dupAddrDetectTransmits uint8
		retransTimer           time.Duration
		expectedRetransTimer   time.Duration
	}{
		{"1:1s:1s", 1, time.Second, time.Second},
		{"2:1s:1s", 2, time.Second, time.Second},
		{"1:2s:2s", 1, 2 * time.Second, 2 * time.Second},
		// 0.4s is an invalid RetransTimer timer and will be fixed to
		// the default RetransTimer value of 1s.
		{"1:0.4s:1s", 1, 400 * time.Millisecond, time.Second},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := stack.Options{}
			opts.NDPConfigs.RetransTimer = test.retransTimer
			opts.NDPConfigs.DupAddrDetectTransmits = test.dupAddrDetectTransmits

			e := channel.New(10, 1280, linkAddr1)
			s := stack.New([]string{ipv6.ProtocolName}, []string{icmp.ProtocolName6}, opts)
			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(_) = %s", err)
			}

			if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
				t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
			}

			stat := s.Stats().ICMP.V6PacketsSent.NeighborSolicit

			// Should have sent an NDP NS immediately.
			if got := stat.Value(); got != 1 {
				t.Fatalf("got NeighborSolicit = %d, want = 1")

			}

			// Address should not be considered bound to the NIC yet (DAD ongoing).
			if addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber); err != tcpip.ErrNoLinkAddress {
				t.Fatalf("stack.GetMainNICAddress(_, _) = %s, %s", addr, err)
			}

			expectedTime := time.Duration(uint64(test.expectedRetransTimer) * uint64(test.dupAddrDetectTransmits))

			// Wait for 500ms less than the expectedTime to resolve
			// to make sure the address was still not resolved.
			<-time.After(expectedTime - 500*time.Millisecond)
			if addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber); err != tcpip.ErrNoLinkAddress {
				t.Fatalf("stack.GetMainNICAddress(_, _) = %s, %s", addr, err)
			}

			// Wait for the remaining time (500ms) + 250ms, at which
			// point the address should be resolved.
			<-time.After(750 * time.Millisecond)
			if addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber); err != nil || addr.Address != addr1 {
				t.Fatalf("stack.GetMainNICAddress(_, _) = %s, %s", addr, err)
			}

			// Should not have sent any more NS messages.
			if got := stat.Value(); got != uint64(test.dupAddrDetectTransmits) {
				t.Fatalf("got NeighborSolicit = %d, want = %d", test.dupAddrDetectTransmits)
			}
		})
	}

}

// TestDADRxSolicit tests that DAD fails if another node is detected to be
// performing DAD on the same address.
func TestDADRxSolicit(t *testing.T) {
	opts := stack.Options{}
	opts.NDPConfigs.RetransTimer = time.Second * 2
	opts.NDPConfigs.DupAddrDetectTransmits = stack.DefaultDupAddrDetectTransmits

	e := channel.New(10, 1280, linkAddr1)
	s := stack.New([]string{ipv6.ProtocolName}, []string{icmp.ProtocolName6}, opts)
	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(_) = %s", err)
	}

	if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
		t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
	}

	// Address should not be considered bound to the NIC yet (DAD ongoing).
	if addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber); err != tcpip.ErrNoLinkAddress {
		t.Fatalf("stack.GetMainNICAddress(_, _) = %s, %s", addr, err)
	}

	// Receive an NS to simulate multiple nodes performing DAD on the same
	// address.
	hdr := buffer.NewPrependable(header.IPv6MinimumSize + header.ICMPv6NeighborSolicitMinimumSize)
	pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborSolicitMinimumSize))
	pkt.SetType(header.ICMPv6NeighborSolicit)
	ns := header.NDPNeighborSolicit(pkt.Body())
	ns.SetTargetAddress(addr1)
	snmc := header.SolicitedNodeAddr(addr1)
	pkt.SetChecksum(header.ICMPv6Checksum(pkt, header.IPv6Any, snmc, buffer.VectorisedView{}))
	payloadLength := hdr.UsedLength()
	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(payloadLength),
		NextHeader:    uint8(icmp.ProtocolNumber6),
		HopLimit:      255,
		SrcAddr:       header.IPv6Any,
		DstAddr:       snmc,
	})

	e.Inject(header.IPv6ProtocolNumber, hdr.View().ToVectorisedView())

	stats := s.Stats().ICMP.V6PacketsReceived
	if got := stats.NeighborSolicit.Value(); got != 1 {
		t.Fatalf("got NeighborSolicit = %d, want = 1")
	}

	// Wait 3 seconds to make sure that DAD did not resolve
	<-time.After(3 * time.Second)
	if addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber); err != tcpip.ErrNoLinkAddress {
		t.Fatalf("stack.GetMainNICAddress(_, _) = %s, %s", addr, err)
	}
}

// TestDADRxAdvert tests that DAD fails if another node is detected to own
// an address we are performing DAD on.
func TestDADRxAdvert(t *testing.T) {
	opts := stack.Options{}
	opts.NDPConfigs.RetransTimer = time.Second * 2
	opts.NDPConfigs.DupAddrDetectTransmits = stack.DefaultDupAddrDetectTransmits

	e := channel.New(10, 1280, linkAddr1)
	s := stack.New([]string{ipv6.ProtocolName}, []string{icmp.ProtocolName6}, opts)
	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(_) = %s", err)
	}

	if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
		t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
	}

	// Address should not be considered bound to the NIC yet (DAD ongoing).
	if addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber); err != tcpip.ErrNoLinkAddress {
		t.Fatalf("stack.GetMainNICAddress(_, _) = %s, %s", addr, err)
	}

	// Receive an NA to simulate multiple notes performing DAD on the same
	// address.
	hdr := buffer.NewPrependable(header.IPv6MinimumSize + header.ICMPv6NeighborAdvertSize)
	pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborAdvertSize))
	pkt.SetType(header.ICMPv6NeighborAdvert)
	na := header.NDPNeighborAdvert(pkt.Body())
	na.SetSolicitedFlag(true)
	na.SetOverrideFlag(true)
	na.SetTargetAddress(addr1)
	pkt.SetChecksum(header.ICMPv6Checksum(pkt, addr1, header.IPv6AllNodesMulticastAddress, buffer.VectorisedView{}))
	payloadLength := hdr.UsedLength()
	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(payloadLength),
		NextHeader:    uint8(icmp.ProtocolNumber6),
		HopLimit:      255,
		SrcAddr:       addr1,
		DstAddr:       header.IPv6AllNodesMulticastAddress,
	})

	e.Inject(header.IPv6ProtocolNumber, hdr.View().ToVectorisedView())

	stats := s.Stats().ICMP.V6PacketsReceived
	if got := stats.NeighborAdvert.Value(); got != 1 {
		t.Fatalf("got NeighborAdvert = %d, want = 1")
	}

	// Wait 3 seconds to make sure that DAD did not resolve
	<-time.After(3 * time.Second)
	if addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber); err != tcpip.ErrNoLinkAddress {
		t.Fatalf("stack.GetMainNICAddress(_, _) = %s, %s", addr, err)
	}
}
