package ipsecservice

import (
	"fmt"
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
	"go.ligato.io/vpp-agent/v3/pkg/models"
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
func (rndr *Renderer) AddServiceConfig(sp *config.SaseServiceConfig, reSync bool) error {
	// Check for service config type
	switch sp.Config.(type) {
	case *sasemodel.SaseConfig:
		rndr.AddPolicy(sp.ServiceInfo, sp.Config.(*sasemodel.SaseConfig), reSync)
	case *sasemodel.IPSecVpnTunnel:
		rndr.AddIPinIPVpnTunnel(sp.ServiceInfo, sp.Config.(*sasemodel.IPSecVpnTunnel), reSync)
	case *sasemodel.SecurityAssociation:
		rndr.AddSecurityAssociation(sp.ServiceInfo, sp.Config.(*sasemodel.SecurityAssociation), reSync)
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
func (rndr *Renderer) AddIPinIPVpnTunnel(serviceInfo *common.ServiceInfo, sp *sasemodel.IPSecVpnTunnel, reSync bool) error {
	vppIPIPTunnel := &vpp_interfaces.IPIPLink{
		TunnelMode: vpp_interfaces.IPIPLink_POINT_TO_POINT,
		SrcAddr:    sp.TunnelSourceIp,
		DstAddr:    sp.TunnelDestinationIp,
	}

	vppIPinIPInterface := &vpp_interfaces.Interface{
		Name:    sp.TunnelName,
		Type:    vpp_interfaces.Interface_IPIP_TUNNEL,
		Enabled: true,
		Link: &vpp_interfaces.Interface_Ipip{
			Ipip: vppIPIPTunnel,
		},
	}

	// Check for Tunnel Interface IP configuration
	if sp.InterfaceType == config.UnnumberedIP {
		intfName := rndr.GetInterfaceNameWithIP(serviceInfo, sp.TunnelSourceIp)
		rndr.Log.Debug("AddIPinIPVpnTunnel: unnummbered Interface: ", intfName)
		if intfName != config.Invalid {
			vppIPinIPInterface.Unnumbered = &vpp_interfaces.Interface_Unnumbered{
				InterfaceWithIp: intfName,
			}
		}
	} else {
		vppIPinIPInterface.IpAddresses = append(vppIPinIPInterface.IpAddresses, sp.TunnelSourceIp)
	}

	rndr.Log.Info("AddIPinIPVpnTunnel: vppIPinIPInterface: ", vppIPinIPInterface)

	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_interfaces.InterfaceKey(vppIPinIPInterface.Name), vppIPinIPInterface, config.Add)
	}

	// Commit is for local base vpp vswitch
	if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
		rndr.Log.Info(" AddIPinIPVpnTunnel: Post txn to local vpp agent",
			"Key: ", vpp_interfaces.InterfaceKey(vppIPinIPInterface.Name), "Value: ", vppIPinIPInterface)
		if reSync == true {
			txn := rndr.ResyncTxnFactory()
			txn.Put(vpp_interfaces.InterfaceKey(vppIPinIPInterface.Name), vppIPinIPInterface)
		} else {
			txn := rndr.UpdateTxnFactory(fmt.Sprintf("IPinIPVpnTunnel %s", vpp_interfaces.InterfaceKey(vppIPinIPInterface.Name)))
			txn.Put(vpp_interfaces.InterfaceKey(vppIPinIPInterface.Name), vppIPinIPInterface)
		}
	} else {
		renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_interfaces.InterfaceKey(vppIPinIPInterface.Name), vppIPinIPInterface, config.Add)
	}

	// Add default saIn and saOut for now - VENKAT TBD
	var saIn, saOut []uint32
	saIn = append(saIn, uint32(config.DefaultInboundSAIndex))
	saOut = append(saOut, uint32(config.DefaultOutboundSAIndex))

	rndr.Log.Info("AddIPinIPVpnTunnel: Protect the Tunnel with SA: ")
	return rndr.IPinIPVpnTunnelProtectionAdd(serviceInfo, sp.TunnelName, saIn, saOut, reSync)
}

// DeleteIPinIPVpnTunnel deletes an existing ip in ip vpn tunnel
func (rndr *Renderer) DeleteIPinIPVpnTunnel(serviceInfo *common.ServiceInfo, sp *sasemodel.IPSecVpnTunnel) error {

	// Delete Tunnel Protection. VENKAT: To have some check to suggest if tunnel protect is
	// enabled or not - TBD
	err := rndr.IPinIPVpnTunnelProtectionDelete(serviceInfo, sp.TunnelName)
	if err != nil {
		rndr.Log.Debug("IPinIPVpnTunnelProtectionDelete: return error", err)
	}

	vppIPinIPInterface := &vpp_interfaces.Interface{
		Name: sp.TunnelName,
	}

	rndr.Log.Infof("DeleteIPinIPVpnTunnel: vppIPinIPInterface: %v", vppIPinIPInterface)

	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_interfaces.InterfaceKey(vppIPinIPInterface.Name), vppIPinIPInterface, config.Delete)
	}

	// Commit is for local base vpp vswitch
	if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
		rndr.Log.Infof(" DeleteIPinIPVpnTunnel: Post txn to local vpp agent",
			"Key: ", vpp_interfaces.InterfaceKey(vppIPinIPInterface.Name), "Value: %v", vppIPinIPInterface)
		txn := rndr.UpdateTxnFactory(fmt.Sprintf("IPinIPVpnTunnel %s", vpp_interfaces.InterfaceKey(vppIPinIPInterface.Name)))
		txn.Delete(vpp_interfaces.InterfaceKey(vppIPinIPInterface.Name))
		return nil
	}

	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_interfaces.InterfaceKey(vppIPinIPInterface.Name), vppIPinIPInterface, config.Delete)
}

/////////////////// IPinIP Tunnel Protect Routines /////////////////

// IPinIPVpnTunnelProtectionAdd :
func (rndr *Renderer) IPinIPVpnTunnelProtectionAdd(serviceInfo *common.ServiceInfo, tunnelName string, saIn, saOut []uint32, reSync bool) error {

	tunnelProtect := &vpp_ipsec.TunnelProtection{
		Interface: tunnelName,
		SaIn:      saIn,
		SaOut:     saOut,
	}

	rndr.Log.Info("IPinIPVpnTunnelProtectionAdd: tunnelProtect: ", tunnelProtect)

	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), models.Key(tunnelProtect), tunnelProtect, config.Add)
	}

	// Commit is for local base vpp vswitch
	if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
		rndr.Log.Info(" IPinIPVpnTunnelProtectionAdd: Post txn to local vpp agent",
			"Key: ", models.Key(tunnelProtect), "Value: ", tunnelProtect)
		if reSync == true {
			txn := rndr.ResyncTxnFactory()
			txn.Put(models.Key(tunnelProtect), tunnelProtect)
		} else {
			txn := rndr.UpdateTxnFactory(fmt.Sprintf("IPinIPVpnTunnelProtectionAdd %s", models.Key(tunnelProtect)))
			txn.Put(models.Key(tunnelProtect), tunnelProtect)
		}
		return nil
	}

	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), models.Key(tunnelProtect), tunnelProtect, config.Add)

}

// IPinIPVpnTunnelProtectionDelete :
func (rndr *Renderer) IPinIPVpnTunnelProtectionDelete(serviceInfo *common.ServiceInfo, tunnelName string) error {

	tunnelProtect := &vpp_ipsec.TunnelProtection{
		Interface: tunnelName,
	}

	rndr.Log.Info("IPinIPVpnTunnelProtectionDelete: tunnelProtect: ", tunnelProtect)

	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), models.Key(tunnelProtect), tunnelProtect, config.Delete)
	}

	// Commit is for local base vpp vswitch
	if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
		rndr.Log.Info(" IPinIPVpnTunnelProtectionDelete: Post txn to local vpp agent",
			"Key: ", models.Key(tunnelProtect), "Value: ", tunnelProtect)
		txn := rndr.UpdateTxnFactory(fmt.Sprintf("IPinIPVpnTunnelProtectionDelete %s", models.Key(tunnelProtect)))
		txn.Delete(models.Key(tunnelProtect))
		return nil
	}

	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), models.Key(tunnelProtect), tunnelProtect, config.Delete)
}

////////////////// IPSec VPN Tunnel Config Handlers //////////////////////////////////

// AddSecurityAssociation adds new security association
// VENKAT: Optimize it to avoid intermediate conversion
// Default Auth and Encryption algorithms initially. To Extend
func (rndr *Renderer) AddSecurityAssociation(serviceInfo *common.ServiceInfo, sp *sasemodel.SecurityAssociation, reSync bool) error {

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

	rndr.Log.Info("AddSecurityAssociation: vppSaInbound: ", vppSaIn)
	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaIn.Index), vppSaIn, config.Add)
	}

	// Commit is for local base vpp vswitch
	if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
		rndr.Log.Info(" AddSecurityAssociation InBound: Post txn to local vpp agent",
			"Key: ", vpp_ipsec.SAKey(vppSaIn.Index), "Value: ", vppSaIn)
		if reSync == true {
			txn := rndr.ResyncTxnFactory()
			txn.Put(vpp_ipsec.SAKey(vppSaIn.Index), vppSaIn)
		} else {
			txn := rndr.UpdateTxnFactory(fmt.Sprintf("AddSecurityAssociation %s", vpp_ipsec.SAKey(vppSaIn.Index)))
			txn.Put(vpp_ipsec.SAKey(vppSaIn.Index), vppSaIn)
		}
	} else {
		// Commit is for remote VPP based CNF
		renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaIn.Index), vppSaIn, config.Add)
	}

	vppSaOut := &vpp_ipsec.SecurityAssociation{
		Index:     config.DefaultOutboundSAIndex,
		Spi:       config.DefaultOutboundSPIIndex,
		Protocol:  vpp_ipsec.SecurityAssociation_ESP,
		IntegAlg:  vpp_ipsec.IntegAlg_SHA1_96,
		IntegKey:  sp.AuthSharedKey,
		CryptoAlg: vpp_ipsec.CryptoAlg_AES_CBC_128,
		CryptoKey: sp.EncryptSharedKey,
	}

	rndr.Log.Info("AddSecurityAssociation: vppSaOutbound: ", vppSaOut)
	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaOut.Index), vppSaOut, config.Add)
	}

	// Commit is for local base vpp vswitch
	if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
		rndr.Log.Info(" AddSecurityAssociation OutBound: Post txn to local vpp agent",
			"Key: ", vpp_ipsec.SAKey(vppSaOut.Index), "Value: ", vppSaOut)
		if reSync == true {
			txn := rndr.ResyncTxnFactory()
			txn.Put(vpp_ipsec.SAKey(vppSaOut.Index), vppSaOut)
		} else {
			txn := rndr.UpdateTxnFactory(fmt.Sprintf("AddSecurityAssociation %s", vpp_ipsec.SAKey(vppSaOut.Index)))
			txn.Put(vpp_ipsec.SAKey(vppSaOut.Index), vppSaOut)
		}
	} else {
		// Commit is for remote VPP based CNF
		renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaOut.Index), vppSaOut, config.Add)
	}
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

	rndr.Log.Info("DeleteSecurityAssociation: vppSaInbound: ", vppSaIn)
	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaIn.Index), vppSaIn, config.Delete)
	}

	// Commit is for local base vpp vswitch
	if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
		rndr.Log.Info(" DeleteSecurityAssociation InBound: Post txn to local vpp agent",
			"Key: ", vpp_ipsec.SAKey(vppSaIn.Index), "Value: ", vppSaIn)
		txn := rndr.UpdateTxnFactory(fmt.Sprintf("DeleteSecurityAssociation %s", vpp_ipsec.SAKey(vppSaIn.Index)))
		txn.Delete(vpp_ipsec.SAKey(vppSaIn.Index))
	} else {

		renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaIn.Index), vppSaIn, config.Delete)
	}

	vppSaOut := &vpp_ipsec.SecurityAssociation{
		Index: config.DefaultOutboundSAIndex,
	}

	rndr.Log.Infof("DeleteSecurityAssociation: vppSaOutbound: %v", vppSaOut)
	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaOut.Index), vppSaOut, config.Delete)
	}

	// Commit is for local base vpp vswitch
	if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
		rndr.Log.Info(" DeleteSecurityAssociation OutBound: Post txn to local vpp agent",
			"Key: ", vpp_ipsec.SAKey(vppSaOut.Index), "Value: ", vppSaOut)
		txn := rndr.UpdateTxnFactory(fmt.Sprintf("DeleteSecurityAssociation %s", vpp_ipsec.SAKey(vppSaOut.Index)))
		txn.Delete(vpp_ipsec.SAKey(vppSaOut.Index))
	} else {
		renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_ipsec.SAKey(vppSaOut.Index), vppSaOut, config.Delete)
	}

	return nil
}

////////////////////// Helper Function to interact with other Contiv Plugins /////////////////////

// GetInterfaceNameWithIP : Return Interface Name for the given IP Address
func (rndr *Renderer) GetInterfaceNameWithIP(serviceInfo *common.ServiceInfo, ipAddress string) string {

	// Base VPP vSwitch. Get information from Contiv Conf API
	// VENKAT: TBD. Can we listen to nodeConfig crd and cache information??
	if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
		// Check Main VPP Interfaces
		ipWithNetworks := rndr.ContivConf.GetMainInterfaceConfiguredIPs()
		rndr.Log.Info("GetInterfaceNameWithIP: ipWithNetworks for MainVPPInterface: ", ipWithNetworks)
		for _, ipNet := range ipWithNetworks {
			if ipNet.Address.String() == ipAddress {
				return rndr.ContivConf.GetMainInterfaceName()
			}
		}
		// Check Other VPP Interfaces
		otherVppInterfaces := rndr.ContivConf.GetOtherVPPInterfaces()
		rndr.Log.Info("GetInterfaceNameWithIP: otherVppInterfaces: ", otherVppInterfaces)
		for _, oVppIntf := range otherVppInterfaces {
			for _, ipNet := range oVppIntf.IPs {
				if ipNet.Address.String() == ipAddress {
					return oVppIntf.InterfaceName
				}
			}
		}
	}

	return config.Invalid
}

////////////////// IPSec VPN Policy handlers //////////////////////////////////

// AddPolicy adds ipsec related policies
func (rndr *Renderer) AddPolicy(serviceInfo *common.ServiceInfo, sp *sasemodel.SaseConfig, reSync bool) error {
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
