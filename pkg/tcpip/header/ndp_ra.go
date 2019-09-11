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

import (
	"encoding/binary"
	"time"
)

// NDPRouterAdvert is an NDP Router Advertisement message. It will only contain
// the body of an ICMPv6 packet.
//
// See RFC 4861 section 4.2 for more details.
type NDPRouterAdvert []byte

const (
	// NDPRAMinimumSize is the minimum size of a valid NDP Router
	// Advertisement message (body of an ICMPv6 packet).
	NDPRAMinimumSize = 12

	// NDPRACurrHopLimitOffset is the byte of the Curr Hop Limit field
	// within an NDPRouterAdvert.
	NDPRACurrHopLimitOffset = 0

	// NDPRAFlagsOffset is the byte with the NDP RA bit-fields/flags
	// within an NDPRouterAdvert.
	NDPRAFlagsOffset = 1

	// NDPRAManagedAddrConfFlagMask is the mask of the Managed Address
	// Configuration flag within the bit-field/flags byte of an
	// NDPRouterAdvert.
	NDPRAManagedAddrConfFlagMask = (1 << 7)

	// NDPRAOtherConfFlagMask is the mask of the Other Configuration flag
	// within the bit-field/flags byte of an NDPRouterAdvert.
	NDPRAOtherConfFlagMask = (1 << 6)

	// NDPRARouterLifetimeOffset is the start of the 2-byte Router Lifetime
	// field within an NDPRouterAdvert.
	NDPRARouterLifetimeOffset = 2

	// NDPRARouterLifetimeLength is the length of the Router Lifetime field
	// in bytes.
	NDPRARouterLifetimeLength = 2

	// NDPRAReachableTimeOffset is the start of the 4-byte Reachable Time
	// field within an NDPRouterAdvert.
	NDPRAReachableTimeOffset = 4

	// NDPRAReachableTimeLength is the length of the Reachable Time field
	// in bytes.
	NDPRAReachableTimeLength = 4

	// NDPRARetransTimerOffset is the start of the 4-byte Retrans Timer
	// field within an NDPRouterAdvert.
	NDPRARetransTimerOffset = 8

	// NDPRARetransTimerLength is the length of the Reachable Time field
	// in bytes.
	NDPRARetransTimerLength = 4

	// NDPRAOptionsOffset is the start of the NDP options in an
	// NDPRouterAdvert.
	NDPRAOptionsOffset = 12
)

// CurrHopLimit returns the value of the Curr Hop Limit field.
func (b NDPRouterAdvert) CurrHopLimit() uint8 {
	return b[NDPRACurrHopLimitOffset]
}

// ManagedAddrConfFlag returns the value of the Managed Address Configuration
// flag.
func (b NDPRouterAdvert) ManagedAddrConfFlag() bool {
	return b[NDPRAFlagsOffset]&NDPRAManagedAddrConfFlagMask != 0
}

// OtherConfFlag returns the value of the Other Configuration flag.
func (b NDPRouterAdvert) OtherConfFlag() bool {
	return b[NDPRAFlagsOffset]&NDPRAOtherConfFlagMask != 0
}

// RouterLifetime returns the lifetime associated with the default router. A
// value of 0 means the source of the Router Advertisement is not a default
// router and SHOULD NOT appear on the default router list. Note, a value of 0
// only means that the router should not be used as a default router, it does
// not apply to other information contained in the Router Advertisement.
func (b NDPRouterAdvert) RouterLifetime() time.Duration {
	// The field is the time in seconds, as per RFC 4861 section 4.2.
	return time.Second * time.Duration(binary.BigEndian.Uint16(b[NDPRARouterLifetimeOffset:][:NDPRARouterLifetimeLength]))
}

// ReachableTime returns the time that a node assumes a neighbor is reachable
// after having received a reachability confirmation. A value of 0 means
// that it is unspecified by the source of the Router Advertisement message.
func (b NDPRouterAdvert) ReachableTime() time.Duration {
	// The field is the time in milliseconds, as per RFC 4861 section 4.2.
	return time.Millisecond * time.Duration(binary.BigEndian.Uint32(b[NDPRAReachableTimeOffset:][:NDPRAReachableTimeLength]))
}

// RetransTimer returns the time between retransmitted Neighbor Solicitation
// messages. A value of 0 means that it is unspecified by the source of the
// Router Advertisement message.
func (b NDPRouterAdvert) RetransTimer() time.Duration {
	// The field is the time in milliseconds, as per RFC 4861 section 4.2.
	return time.Millisecond * time.Duration(binary.BigEndian.Uint32(b[NDPRARetransTimerOffset:][:NDPRARetransTimerLength]))
}

// Options returns an NDPOptions of the the options body.
func (b NDPRouterAdvert) Options() NDPOptions {
	return NDPOptions(b[NDPRAOptionsOffset:])
}
