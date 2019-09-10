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

package stack

import (
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	// DefaultDupAddrDetectTransmits is the default number of NDP Neighbor
	// Solicitation messages to send when doing Duplicate Address Detection
	// for a tentative address.
	//
	// Default = 1.
	DefaultDupAddrDetectTransmits = 1

	// DefaultRetransTimer is the default amount of time to wait between
	// sending NDP Neighbor solicitation messages.
	//
	// Default = 1s.
	DefaultRetransTimer = time.Second

	// MinimumRetransTimer is the minimum amount of time to wait between
	// sending NDP Neighbor solicitation messages.
	//
	// Min = 0.5s.
	MinimumRetransTimer = 500 * time.Millisecond
)

// NDPConfigurations is the NDP configurations for the netstack.
type NDPConfigurations struct {
	// The number of Neighbor Solicitation messages to send when doing
	// Duplicate Address Detection for a tentative address.
	//
	// Note, a value of zero effectively disables DAD.
	DupAddrDetectTransmits uint8

	// The amount of time to wait between sending Neighbor solicitation
	// messages.
	//
	// Must be greater than 0.5s.
	RetransTimer time.Duration
}

// fix fixes NDP values to make sure valid values are used.
//
// If RetransTimer is less than 0.5s, then a value of DefaultRetransTimer will
// be used.
func (c *NDPConfigurations) fix() {
	if c.RetransTimer < MinimumRetransTimer {
		c.RetransTimer = DefaultRetransTimer
	}
}

// DADState is the Duplicate Address Detection related state.
type DADState struct {
	// The number of remaining NS messages to send before we can conclude
	// that an address is not a duplicate on a link.
	remaining uint8

	// The DAD timer to send the next NS message, or resolve the address.
	timer *time.Timer
}

// NDPState is the per-interface NDP state.
type NDPState struct {
	// dad is the state associated with Duplicate Address Detection for
	// IPv6 addresses.
	dad map[tcpip.Address]*DADState
}

// newNDPState creates and returns an empty NDPState.
func newNDPState() NDPState {
	return NDPState{
		dad: make(map[tcpip.Address]*DADState),
	}
}

// startDuplicateAddressDetection performs Duplicate Address Detection.
//
// This function must only be called by IPv6 addresses that are currently
// tentative.
func (ndp *NDPState) startDuplicateAddressDetection(n *NIC, addr tcpip.Address, ref *referencedNetworkEndpoint) *tcpip.Error {
	// addr must be an IPv6 address.
	if len(addr) != 16 {
		return tcpip.ErrAddressFamilyNotSupported
	}

	// addr must currently be tentative.
	if ref.kind != permanentTentative {
		return tcpip.ErrInvalidEndpointState
	}

	ndpConfigs := &n.stack.ndpConfigs
	if ndpConfigs.DupAddrDetectTransmits == 0 {
		// Assign immediately.
		ref.kind = permanent
	} else {
		// do DAD.
		ndp.dad[addr] = &DADState{remaining: ndpConfigs.DupAddrDetectTransmits, timer: nil}
		if err := ndp.doDuplicateAddressDetection(n, addr); err != nil {
			return err
		}
	}

	return nil
}

// doDuplicateAddressDetection is called on every iteration of the timer, and
// when DAD starts.
//
// This function must only be called by IPv6 addresses that are currently
// tentative.
func (ndp *NDPState) doDuplicateAddressDetection(n *NIC, addr tcpip.Address) *tcpip.Error {
	dad, ok := ndp.dad[addr]
	if !ok {
		return tcpip.ErrBadAddress
	}

	dad.timer = nil

	ref, ok := n.endpoints[NetworkEndpointID{addr}]
	if !ok {
		// We should have an endpoint for addr since we are
		// still performing DAD on it.
		return tcpip.ErrBadAddress
	}

	if ref.kind != permanentTentative {
		// The endpoint should still be marked as tentative
		// since we are still performing DAD on it.
		return tcpip.ErrInvalidEndpointState
	}

	if dad.remaining == 0 {
		// DAD has resolved.
		ref.kind = permanent
	} else {
		dad.remaining--

		// Send a new NS.
		snmc := header.SolicitedNodeAddr(addr)
		snmcRef, ok := n.endpoints[NetworkEndpointID{snmc}]
		if !ok {
			// This should never happen, but just in case.
			return tcpip.ErrBadAddress
		}

		// Use the unspecified address as the source address when
		// performing DAD.
		r := makeRoute(header.IPv6ProtocolNumber, header.IPv6Any, snmc, n.linkEP.LinkAddress(), snmcRef, false, false)

		hdr := buffer.NewPrependable(int(r.MaxHeaderLength()) + header.ICMPv6NeighborSolicitMinimumSize)
		pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborSolicitMinimumSize))
		pkt.SetType(header.ICMPv6NeighborSolicit)
		ns := header.NDPNeighborSolicit(pkt.Body())
		ns.SetTargetAddress(addr)
		pkt.SetChecksum(header.ICMPv6Checksum(pkt, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))

		sent := r.Stats().ICMP.V6PacketsSent
		if err := r.WritePacket(nil, hdr, buffer.VectorisedView{}, header.ICMPv6ProtocolNumber, r.DefaultTTL()); err != nil {
			sent.Dropped.Increment()
			return err
		}
		sent.NeighborSolicit.Increment()

		dad.timer = time.AfterFunc(n.stack.ndpConfigs.RetransTimer, func() {
			n.mu.Lock()
			defer n.mu.Unlock()

			n.ndp.doDuplicateAddressDetection(n, addr)
		})
	}

	return nil
}

// stopDuplicateAddressDetection ends a running Duplicate Address Detection
// process. Note, this may leave the DAD process for a tentative address in
// such a state forever, unless some other external event resolves the DAD
// process (receiving an NA from the true owner of addr, or an NS for addr
// (implying another node is attempting to use addr)). It is up to the caller
// of this function to handle such a scenario. Normally, addr will be removed
// from n right after this function returns.
func (ndp *NDPState) stopDuplicateAddressDetection(n *NIC, addr tcpip.Address) *tcpip.Error {
	// TODO
	return nil

	dad, ok := ndp.dad[addr]
	if !ok {
		// Not currently performing DAD on addr, just return.
		return nil
	}

	// If we have a timer set, stop it.
	if dad.timer != nil {
		dad.timer.Stop()
		dad.timer = nil
	}

	// Delete DAD state for addr.
	delete(ndp.dad, addr)

	return nil
}
