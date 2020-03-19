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
	"github.com/contiv/vpp/plugins/sase/renderer"
	"github.com/contiv/vpp/plugins/statscollector"
	"go.ligato.io/cn-infra/v2/logging"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
	vpp_ipsec "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/ipsec"
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
	MockTest         bool
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
		rndr.AddIPinIPVpnTunnel(sp.ServiceInfo, sp.Config.(*sasemodel.IPSecVpnTunnel))
	case *sasemodel.SecurityAssociation:
		rndr.AddSecurityAssociation(sp.ServiceInfo, sp.Config.(*sasemodel.SecurityAssociation))
	default:
	}
	return nil
}

// UpdateServiceConfig :
func (rndr *Renderer) UpdateServiceConfig(old, new *config.SaseServiceConfig) error {
	// Check for service config type
	switch new.Config.(type) {
	case *sasemodel.SaseConfig:
		rndr.UpdatePolicy(new.ServiceInfo, old.Config.(*sasemodel.SaseConfig),
			new.Config.(*sasemodel.SaseConfig))
	case *sasemodel.IPSecVpnTunnel:
		rndr.UpdateIPSecVpnTunnel(new.ServiceInfo, new.Config.(*sasemodel.IPSecVpnTunnel),
			old.Config.(*sasemodel.IPSecVpnTunnel))
	case *sasemodel.SecurityAssociation:
		rndr.UpdateSecurityAssociation(new.ServiceInfo, new.Config.(*sasemodel.SecurityAssociation),
			old.Config.(*sasemodel.SecurityAssociation))
	default:
	}
	return nil
}

// DeleteServiceConfig :
func (rndr *Renderer) DeleteServiceConfig(sp *config.SaseServiceConfig) error {
	// Check for service config type
	switch sp.Config.(type) {
	case *sasemodel.SaseConfig:
		rndr.DeletePolicy(sp.ServiceInfo, sp.Config.(*sasemodel.SaseConfig))
	case *sasemodel.IPSecVpnTunnel:
		rndr.DeleteIPinIPVpnTunnel(sp.ServiceInfo, sp.Config.(*sasemodel.IPSecVpnTunnel))
	case *sasemodel.SecurityAssociation:
		rndr.DeleteSecurityAssociation(sp.ServiceInfo, sp.Config.(*sasemodel.SecurityAssociation))
	default:
	}

	return nil
}

////////////////// IPSec VPN Tunnel Config Handlers //////////////////////////////////
// https://docs.ligato.io/en/latest/plugins/vpp-plugins/#ipsec-plugin

// AddIPSecVpnTunnel adds ipsec vpn tunnel
func (rndr *Renderer) AddIPSecVpnTunnel(serviceInfo *common.ServiceInfo, sp *sasemodel.IPSecVpnTunnel) error {
	vppIPSecTunnel := &vpp_interfaces.IPSecLink{
		LocalIp:   sp.TunnelSourceIp,
		RemoteIp:  sp.TunnelDestinationIp,
		LocalSpi:  config.DefaultOutboundSPIIndex,
		RemoteSpi: config.DefaultInboundSPIIndex,
	}

	vppIPSecInterface := &vpp_interfaces.Interface{
		Name:        sp.TunnelName,
		Type:        vpp_interfaces.Interface_IPSEC_TUNNEL,
		Enabled:     true,
		IpAddresses: []string{sp.TunnelSourceIp},
		Link: &vpp_interfaces.Interface_Ipsec{
			Ipsec: vppIPSecTunnel,
		},
	}

	rndr.Log.Infof("AddIPSecVpnTunnel: vppIPSecInterface: %v", vppIPSecInterface)

	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_interfaces.InterfaceKey(vppIPSecInterface.Name), vppIPSecInterface, config.Add)
	}

	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_interfaces.InterfaceKey(vppIPSecInterface.Name), vppIPSecInterface, config.Add)
}

// UpdateIPSecVpnTunnel updates exiting ipsec vpn tunnel
func (rndr *Renderer) UpdateIPSecVpnTunnel(serviceInfo *common.ServiceInfo, old, new *sasemodel.IPSecVpnTunnel) error {
	return nil
}

// DeleteIPSecVpnTunnel deletes an existing ipsec vpn tunnel
func (rndr *Renderer) DeleteIPSecVpnTunnel(serviceInfo *common.ServiceInfo, sp *sasemodel.IPSecVpnTunnel) error {

	vppIPSecInterface := &vpp_interfaces.Interface{
		Name: sp.TunnelName,
	}

	rndr.Log.Infof("DeleteIPSecVpnTunnel: vppIPSecInterface: %v", vppIPSecInterface)

	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_interfaces.InterfaceKey(vppIPSecInterface.Name), vppIPSecInterface, config.Delete)
	}

	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_interfaces.InterfaceKey(vppIPSecInterface.Name), vppIPSecInterface, config.Delete)

}

///////////////////// IPinIP Tunnel Routines //////////////////

// AddIPinIPVpnTunnel adds ip in ip vpn tunnel
func (rndr *Renderer) AddIPinIPVpnTunnel(serviceInfo *common.ServiceInfo, sp *sasemodel.IPSecVpnTunnel) error {
	vppIPIPTunnel := &vpp_interfaces.IPIPLink{
		TunnelMode: vpp_interfaces.IPIPLink_POINT_TO_POINT,
		SrcAddr:    sp.TunnelSourceIp,
		DstAddr:    sp.TunnelDestinationIp,
	}

	vppIPinIPInterface := &vpp_interfaces.Interface{
		Name:        sp.TunnelName,
		Type:        vpp_interfaces.Interface_IPIP_TUNNEL,
		Enabled:     true,
		IpAddresses: []string{sp.TunnelSourceIp},
		Link: &vpp_interfaces.Interface_Ipip{
			Ipip: vppIPIPTunnel,
		},
	}

	rndr.Log.Infof("AddIPinIPVpnTunnel: vppIPinIPInterface: %v", vppIPinIPInterface)

	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_interfaces.InterfaceKey(vppIPinIPInterface.Name), vppIPinIPInterface, config.Add)
	}

	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_interfaces.InterfaceKey(vppIPinIPInterface.Name), vppIPinIPInterface, config.Add)
}

// DeleteIPinIPVpnTunnel deletes an existing ip in ip vpn tunnel
func (rndr *Renderer) DeleteIPinIPVpnTunnel(serviceInfo *common.ServiceInfo, sp *sasemodel.IPSecVpnTunnel) error {

	vppIPinIPInterface := &vpp_interfaces.Interface{
		Name: sp.TunnelName,
	}

	rndr.Log.Infof("DeleteIPinIPVpnTunnel: vppIPinIPInterface: %v", vppIPinIPInterface)

	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_interfaces.InterfaceKey(vppIPinIPInterface.Name), vppIPinIPInterface, config.Delete)
	}

	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_interfaces.InterfaceKey(vppIPinIPInterface.Name), vppIPinIPInterface, config.Delete)

}

/////////////////// IPinIP Tunnel Protect Routines /////////////////

// IPinIPVpnTunnelProtectionAdd :
func (rndr *Renderer) IPinIPVpnTunnelProtectionAdd(tunnelName string, saIn, saOut []uint32) error {

	tunnelProtect := &vpp_ipsec.TunnelProtection{}

	rndr.Log.Infof("IPinIPVpnTunnelProtectionAdd: tunnelProtect: %v", tunnelProtect)
	return nil
}

// IPinIPVpnTunnelProtectionDelete :
func (rndr *Renderer) IPinIPVpnTunnelProtectionDelete(serviceInfo *common.ServiceInfo, sp *sasemodel.IPSecVpnTunnel) error {

	return nil

}

////////////////// IPSec VPN Tunnel Config Handlers //////////////////////////////////

// AddSecurityAssociation adds new security association
// VENKAT: Optimize it to avoid intermediate conversion
// Default Auth and Encryption algorithms initially. To Extend
func (rndr *Renderer) AddSecurityAssociation(serviceInfo *common.ServiceInfo, sp *sasemodel.SecurityAssociation) error {

	// Render Inbound and Outbound Security associations
	vppSaIn := &vpp_ipsec.SecurityAssociation{
		Index:     config.DefaultInboundSAIndex,
		Spi:       config.DefaultInboundSPIIndex,
		Protocol:  vpp_ipsec.SecurityAssociation_ESP,
		IntegAlg:  vpp_ipsec.IntegAlg_SHA1_96,
		IntegKey:  sp.AuthSharedKey,
		CryptoAlg: vpp_ipsec.CryptoAlg_AES_CBC_128,
		CryptoKey: sp.EncryptSharedKey,
	}

	rndr.Log.Infof("AddSecurityAssociation: vppSaInbound: %v", vppSaIn)
	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaIn.Index), vppSaIn, config.Add)
	}

	renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaIn.Index), vppSaIn, config.Add)

	vppSaOut := &vpp_ipsec.SecurityAssociation{
		Index:     config.DefaultOutboundSAIndex,
		Spi:       config.DefaultOutboundSPIIndex,
		Protocol:  vpp_ipsec.SecurityAssociation_ESP,
		IntegAlg:  vpp_ipsec.IntegAlg_SHA1_96,
		IntegKey:  sp.AuthSharedKey,
		CryptoAlg: vpp_ipsec.CryptoAlg_AES_CBC_128,
		CryptoKey: sp.EncryptSharedKey,
	}

	rndr.Log.Infof("AddSecurityAssociation: vppSaOutbound: %v", vppSaOut)
	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaOut.Index), vppSaOut, config.Add)
	}
	renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaOut.Index), vppSaOut, config.Add)

	return nil
}

// UpdateSecurityAssociation updates exiting security association
func (rndr *Renderer) UpdateSecurityAssociation(serviceInfo *common.ServiceInfo, old, new *sasemodel.SecurityAssociation) error {
	return nil
}

// DeleteSecurityAssociation deletes an existing Security Association
func (rndr *Renderer) DeleteSecurityAssociation(serviceInfo *common.ServiceInfo, sp *sasemodel.SecurityAssociation) error {

	// Render Inbound and Outbound Security associations
	vppSaIn := &vpp_ipsec.SecurityAssociation{
		Index: config.DefaultInboundSAIndex,
	}

	rndr.Log.Infof("DeleteSecurityAssociation: vppSaInbound: %v", vppSaIn)
	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaIn.Index), vppSaIn, config.Delete)
	}
	renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaIn.Index), vppSaIn, config.Delete)

	vppSaOut := &vpp_ipsec.SecurityAssociation{
		Index: config.DefaultOutboundSAIndex,
	}

	rndr.Log.Infof("DeleteSecurityAssociation: vppSaOutbound: %v", vppSaOut)
	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaOut.Index), vppSaOut, config.Delete)
	}
	renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaOut.Index), vppSaOut, config.Delete)

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

// SecurityAssociations :
type SecurityAssociations struct {
	Name        string
	Index       string
	SpiIndex    uint32
	Protocol    config.ProtocolType
	AuthAlgo    config.CryptoAuth
	AuthKey     string
	EncryptAlgo config.CryptoEncrypt
	EncryptKey  string
}

// SecurityPolicyDefinition :
type SecurityPolicyDefinition struct {
	Name       string
	InboundSa  SecurityAssociations
	OutboundSa SecurityAssociations
	Action     config.SecurityAction
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
