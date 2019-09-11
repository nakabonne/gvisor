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

package header

import "gvisor.dev/gvisor/pkg/tcpip"

// NDPNeighborAdvert is an NDP Neighbor Advertisement message. It will
// only contain the body of an ICMPv6 packet.
//
// See RFC 4861 section 4.4 for more details.
type NDPNeighborAdvert []byte

const (
	// NDPNAMinimumSize is the minimum size of a valid NDP Neighbor
	// Advertisement message (body of an ICMPv6 packet).
	NDPNAMinimumSize = 20

	// NDPNATargetAddessOffset is the start of the Target Address
	// field within an NDPNeighborAdvert.
	NDPNATargetAddessOffset = 4

	// NDPNAOptionsOffset is the start of the NDP options in an
	// NDPNeighborAdvert.
	NDPNAOptionsOffset = NDPNATargetAddessOffset + IPv6AddressSize

	// NDPNAFlagsOffset is the offset of the flags within an
	// NDPNeighborAdvert
	NDPNAFlagsOffset = 0

	// NDPNARouterFlagMask is the mask of the Router Flag field in
	// the flags byte within in an NDPNeighborAdvert.
	NDPNARouterFlagMask = (1 << 7)

	// NDPNASolicitedFlagMask is the mask of the Solicited Flag field in
	// the flags byte within in an NDPNeighborAdvert.
	NDPNASolicitedFlagMask = (1 << 6)

	// NDPNAOverrideFlagMask is the mask of the Override Flag field in
	// the flags byte within in an NDPNeighborAdvert.
	NDPNAOverrideFlagMask = (1 << 5)
)

// TargetAddress returns the value within the Target Address field.
func (b NDPNeighborAdvert) TargetAddress() tcpip.Address {
	return tcpip.Address(b[NDPNATargetAddessOffset:][:IPv6AddressSize])
}

// SetTargetAddress sets the value within the Target Address field.
func (b NDPNeighborAdvert) SetTargetAddress(addr tcpip.Address) {
	copy(b[NDPNATargetAddessOffset:][:IPv6AddressSize], addr)
}

// RouterFlag returns the value of the Router Flag field.
func (b NDPNeighborAdvert) RouterFlag() bool {
	return b[NDPNAFlagsOffset]&NDPNARouterFlagMask != 0
}

// SetRouterFlag sets the value in the Router Flag field.
func (b NDPNeighborAdvert) SetRouterFlag(f bool) {
	if f {
		b[NDPNAFlagsOffset] |= NDPNARouterFlagMask
	} else {
		b[NDPNAFlagsOffset] &^= NDPNARouterFlagMask
	}
}

// SolicitedFlag returns the value of the Solicited Flag field.
func (b NDPNeighborAdvert) SolicitedFlag() bool {
	return b[NDPNAFlagsOffset]&NDPNASolicitedFlagMask != 0
}

// SetSolicitedFlag sets the value in the Solicited Flag field.
func (b NDPNeighborAdvert) SetSolicitedFlag(f bool) {
	if f {
		b[NDPNAFlagsOffset] |= NDPNASolicitedFlagMask
	} else {
		b[NDPNAFlagsOffset] &^= NDPNASolicitedFlagMask
	}
}

// OverrideFlag returns the value of the Override Flag field.
func (b NDPNeighborAdvert) OverrideFlag() bool {
	return b[NDPNAFlagsOffset]&NDPNAOverrideFlagMask != 0
}

// SetOverrideFlag sets the value in the Override Flag field.
func (b NDPNeighborAdvert) SetOverrideFlag(f bool) {
	if f {
		b[NDPNAFlagsOffset] |= NDPNAOverrideFlagMask
	} else {
		b[NDPNAFlagsOffset] &^= NDPNAOverrideFlagMask
	}
}

// Options returns an NDPOptions of the the options body.
func (b NDPNeighborAdvert) Options() NDPOptions {
	return NDPOptions(b[NDPNAOptionsOffset:])
}
