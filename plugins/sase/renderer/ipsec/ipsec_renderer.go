package ipsecservice

import (
	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/sase/config"
	"github.com/contiv/vpp/plugins/sase/renderer"
	"github.com/contiv/vpp/plugins/statscollector"
	"github.com/ligato/cn-infra/logging"
)

// Renderer implements rendering of Nat policies
type Renderer struct {
	Deps
}

// Deps lists dependencies of the Renderer.
type Deps struct {
	Log              logging.Logger
	Config           *config.Config
	ContivConf       contivconf.API
	IPAM             ipam.API
	IPNet            ipnet.API
	UpdateTxnFactory func(change string) (txn controller.UpdateOperations)
	ResyncTxnFactory func() (txn controller.ResyncOperations)
	Stats            statscollector.API /* used for exporting the statistics */
	RemoteDB         nodesync.KVDBWithAtomic
}

// Init initializes the renderer.
func (rndr *Renderer) Init() error {
	if rndr.Config == nil {
		rndr.Config = config.DefaultIPSecConfig()
	}
	return nil
}

// AfterInit starts asynchronous NAT session cleanup.
func (rndr *Renderer) AfterInit() error {
	return nil
}

// AddPolicy adds ipsec related policies
func (rndr *Renderer) AddPolicy(sp *renderer.SaseServicePolicy) error {
	return nil
}

// UpdatePolicy updates exiting ipsecrelated policies
func (rndr *Renderer) UpdatePolicy(old, new *renderer.SaseServicePolicy) error {
	return nil
}

// DeletePolicy deletes an existing ipsecpolicy
func (rndr *Renderer) DeletePolicy(sp *renderer.SaseServicePolicy) error {
	return nil
}

///////////////////// VPN Service Functionality //////////////////
//
// Functionality:
//    1. Establish Secure Tunnel between 2 end points
//    2. Encrpyt all or subset of traffic egress out of Tunnel
//    3. Decrpy all or subset of traffic ingress into the tunnel
//
// Parameters :
//    1. Tunnel EndPoints
//    2. Authentication and Encryption Algorithms and Security Associations/Policy Definitions
//    3. Traffic parameters that needs to be encrypted/decrypted (Applicable in Transport Mode)
//    4. Tunnel Mode - Anything ingress/egress (Protect Tunnel)
//
////////////////////////////////////////////////////////////////////

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

// SecurityAssociations :
type SecurityAssociations struct {
	Name        string
	Protocol    renderer.ProtocolType
	AuthAlgo    CryptoAuth
	AuthKey     string
	EncryptAlgo CryptoEncrypt
	EncryptKey  string
}

// SecurityPolicyDefinition :
type SecurityPolicyDefinition struct {
	Name       string
	InboundSa  SecurityAssociations
	OutboundSa SecurityAssociations
	Action     SecurityAction
}

// IPSecTunnelEndPoint :
type IPSecTunnelEndPoint struct {
	source      string
	destination string
}

// VPNRule :
type VPNRule struct {
	Name           string
	Encap          EncapMode
	Tunnel         IPSecTunnelEndPoint
	SecurityPolicy SecurityPolicyDefinition
}
