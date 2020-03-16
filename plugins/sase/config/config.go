// Copyright (c) 2019 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"github.com/contiv/vpp/plugins/sase/common"
)

// SaseServiceConfig is common abstraction which contains neccessary information that would be
// required by renderer to render the config into dataplane
type SaseServiceConfig struct {
	// Service Info
	ServiceInfo *common.ServiceInfo
	// Config Data (Policies, Security association, IPSecVpnTunnel)
	Config interface{}
}

const (
	// NotRequired : Constant to indicate interface not required
	NotRequired = "notRequired"
)

// Interface : Nat Interface
// Local inside Interface (true) or external Public Interface (false)
// Twice Nat Enabled (true)
type Interface struct {
	Name     string
	VrfID    uint32
	IsLocal  bool
	TwiceNat bool
}

// Subnets : Subnet Addresses
type Subnets struct {
	Vrf    uint32
	Subnet string
	// Any other attributes here for the given subnet??
}

// EventType represents the type of an configuration event processed by the ipnet plugin
type EventType int

const (
	// Resync synchronization of the existing config vs demanded config
	Resync EventType = iota
	// Add addition of new config
	Add
	// Delete deletion of existing config
	Delete
)

// ProtocolType is either TCP or UDP or OTHER.
type ProtocolType int

const (
	// TCP protocol.
	TCP ProtocolType = iota
	// ESP Protocol
	ESP
	// UDP protocol.
	UDP
	// OTHER is some NON-UDP, NON-TCP traffic (used ONLY in unit tests).
	OTHER
	// ANY L4 protocol or even pure L3 traffic (port numbers are ignored).
	ANY
)

// String converts ProtocolType into a human-readable string.
func (at ProtocolType) String() string {
	switch at {
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	case OTHER:
		return "OTHER"
	case ANY:
		return "ANY"
	}
	return "INVALID"
}

////////////////// Security Parameters /////////////////////

// CryptoAuth :
type CryptoAuth int

const (
	// None :
	None CryptoAuth = iota
	// Sha1 :
	Sha1
	// Sha25696 :
	Sha25696
	// Sha256128 :
	Sha256128
	// Sha384192 :
	Sha384192
	// Sha512256 :
	Sha512256
)

// CryptoEncrypt :
type CryptoEncrypt int

const (
	// NoEncrypt :
	NoEncrypt CryptoEncrypt = iota
	// AEScbc128 :
	AEScbc128
	// AEScbc192 :
	AEScbc192
	// AEScbc256 :
	AEScbc256
	// AESctr128 :
	AESctr128
	// AESctr192 :
	AESctr192
	// AESctr256 :
	AESctr256
)

// EncapMode :
type EncapMode int

const (
	// NoEncap :
	NoEncap EncapMode = iota
	// TunnelMode :
	TunnelMode
	// TransportMode :
	TransportMode
)

// SecurityAction :
type SecurityAction int

const (
	// ByPass :
	ByPass SecurityAction = iota
	// Discard :
	Discard
	// Protect :
	Protect
)

// Security associations default parameters
const (
	DefaultInboundSAIndex      = "10"
	DefaultOutboundSAIndex     = "20"
	DefaultInboundSPIIndex     = 1000
	DefaultOutboundSPIIndex    = 1001
	DefaultAuthAlgorithm       = Sha1
	DefaultAuthKey             = "4339314b55523947594d6d3547666b45764e6a58"
	DefaultEncryptionAlgorithm = AEScbc128
	DefaultEncryptionKey       = "4a506a794f574265564551694d653768"
	DefaultProtocol            = ESP
)

// DefaultNatConfig returns configuration for service plugin with default values.
func DefaultNatConfig() *SaseServiceConfig {
	return &SaseServiceConfig{}
}

// DefaultFirewallConfig returns configuration for service plugin with default values.
func DefaultFirewallConfig() *SaseServiceConfig {
	return &SaseServiceConfig{}
}

// DefaultIPSecConfig returns configuration for service plugin with default values.
func DefaultIPSecConfig() *SaseServiceConfig {
	return &SaseServiceConfig{}
}

// DefaultRouteConfig returns configuration for service plugin with default values.
func DefaultRouteConfig() *SaseServiceConfig {
	return &SaseServiceConfig{}
}
