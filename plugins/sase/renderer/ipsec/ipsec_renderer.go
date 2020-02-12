package ipsecservice

import (
	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	sasemodel "github.com/contiv/vpp/plugins/crd/handler/saseconfig/model"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/sase/common"
	"github.com/contiv/vpp/plugins/sase/config"
	"github.com/contiv/vpp/plugins/statscollector"
	"github.com/ligato/cn-infra/logging"
	vpp_interfaces "github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	vpp_ipsec "github.com/ligato/vpp-agent/api/models/vpp/ipsec"
)

// Renderer implements rendering of Nat policies
type Renderer struct {
	Deps
}

// Deps lists dependencies of the Renderer.
type Deps struct {
	Log              logging.Logger
	Config           *config.SaseServiceConfig
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

// DeInit clean up service config
func (rndr *Renderer) DeInit() error {
	return nil
}

// AfterInit starts asynchronous NAT session cleanup.
func (rndr *Renderer) AfterInit() error {
	return nil
}

// AddServiceConfig :
func (rndr *Renderer) AddServiceConfig(sp *config.SaseServiceConfig) error {
	// Check for service config type
	switch sp.Config.(type) {
	case *sasemodel.SaseConfig:
		rndr.AddPolicy(sp.ServiceInfo, sp.Config.(*sasemodel.SaseConfig))
	case *sasemodel.IPSecVpnTunnel:
		rndr.AddIPSecVpnTunnel(sp.ServiceInfo, sp.Config.(*sasemodel.IPSecVpnTunnel))
	case *sasemodel.SecurityAssociation:
		rndr.AddSecurityAssociation(sp.ServiceInfo, sp.Config.(*sasemodel.SecurityAssociation))
	default:
	}
	return nil
}

// UpdateServiceConfig :
func (rndr *Renderer) UpdateServiceConfig(old, new *config.SaseServiceConfig) error {
	return nil
}

// DeleteServiceConfig :
func (rndr *Renderer) DeleteServiceConfig(sp *config.SaseServiceConfig) error {
	return nil
}

////////////////// IPSec VPN Tunnel Config Handlers //////////////////////////////////

// AddIPSecVpnTunnel adds ipsec vpn tunnel
func (rndr *Renderer) AddIPSecVpnTunnel(serviceInfo *common.ServiceInfo, sp *sasemodel.IPSecVpnTunnel) error {
	return nil
}

// UpdateIPSecVpnTunnel updates exiting ipsec vpn tunnel
func (rndr *Renderer) UpdateIPSecVpnTunnel(serviceInfo *common.ServiceInfo, old, new *sasemodel.IPSecVpnTunnel) error {
	return nil
}

// DeleteIPSecVpnTunnel deletes an existing ipsec vpn tunnel
func (rndr *Renderer) DeleteIPSecVpnTunnel(serviceInfo *common.ServiceInfo, sp *sasemodel.IPSecVpnTunnel) error {
	return nil
}

////////////////// IPSec VPN Tunnel Config Handlers //////////////////////////////////

// AddSecurityAssociation adds new security association
func (rndr *Renderer) AddSecurityAssociation(serviceInfo *common.ServiceInfo, sp *sasemodel.SecurityAssociation) error {
	return nil
}

// UpdateSecurityAssociation updates exiting security association
func (rndr *Renderer) UpdateSecurityAssociation(serviceInfo *common.ServiceInfo, old, new *sasemodel.SecurityAssociation) error {
	return nil
}

// DeleteSecurityAssociation deletes an existing Security Association
func (rndr *Renderer) DeleteSecurityAssociation(serviceInfo *common.ServiceInfo, sp *sasemodel.SecurityAssociation) error {
	return nil
}

////////////////// IPSec VPN Policy handlers //////////////////////////////////

// AddPolicy adds ipsec related policies
func (rndr *Renderer) AddPolicy(serviceInfo *common.ServiceInfo, sp *sasemodel.SaseConfig) error {
	return nil
}

// UpdatePolicy updates exiting ipsecrelated policies
func (rndr *Renderer) UpdatePolicy(serviceInfo *common.ServiceInfo, old, new *sasemodel.SaseConfig) error {
	return nil
}

// DeletePolicy deletes an existing ipsecpolicy
func (rndr *Renderer) DeletePolicy(serviceInfo *common.ServiceInfo, sp *sasemodel.SaseConfig) error {
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
	Protocol    config.ProtocolType
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
	Source      string
	Destination string
}

// renderVppSPD :: Renders VPP IPSec Tunnel Interface
func (rndr *Renderer) renderVppIPSecTunnelInterface(key string, tunnel *IPSecTunnelEndPoint) *vpp_interfaces.IPSecLink {
	vppIPSecTunnel := &vpp_interfaces.IPSecLink{}
	return vppIPSecTunnel
}

// renderVppSPD :: Renders VPP IPSec Security Policy Database
func (rndr *Renderer) renderVppSPD(key string, spd *SecurityPolicyDefinition) *vpp_ipsec.SecurityPolicyDatabase {
	vppSpd := &vpp_ipsec.SecurityPolicyDatabase{}
	return vppSpd
}

// renderVppSA :: Renders VPP IPSec Security Association
func (rndr *Renderer) renderVppSA(key string, sa *SecurityAssociations) *vpp_ipsec.SecurityAssociation {
	vppSa := &vpp_ipsec.SecurityAssociation{}
	return vppSa
}
