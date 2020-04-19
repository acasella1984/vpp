/*
 * // Copyright (c) 2017 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

package firewallservice

import (
	//"errors"
	"fmt"
	"net"
	"strings"

	"github.com/gogo/protobuf/proto"

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
	vpp_acl "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/acl"
)

// Renderer implements rendering of firewall policies
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
		rndr.Config = config.DefaultFirewallConfig()
	}
	return nil
}

// DeInit clean up service config
func (rndr *Renderer) DeInit() error {
	return nil
}

// AfterInit starts cleanup.
func (rndr *Renderer) AfterInit() error {
	return nil
}

// AddServiceConfig :
func (rndr *Renderer) AddServiceConfig(sp *config.SaseServiceConfig, reSync bool) error {

	// Check for service config type
	switch sp.Config.(type) {
	case *sasemodel.SaseConfig:
		return rndr.AddSaseConfig(sp.ServiceInfo, sp.Config.(*sasemodel.SaseConfig), reSync)
	case *sasemodel.NetworkFirewallProfile:
		return rndr.CreateNetworkFirewallProfile(sp.ServiceInfo, sp.Config.(*sasemodel.NetworkFirewallProfile), reSync)
	default:
	}
	return nil
}

// UpdateServiceConfig :
func (rndr *Renderer) UpdateServiceConfig(old, new *config.SaseServiceConfig) error {

	// Check for service config type
	switch new.Config.(type) {
	case *sasemodel.SaseConfig:
		return rndr.UpdateSaseConfig(new.ServiceInfo,
			old.Config.(*sasemodel.SaseConfig), new.Config.(*sasemodel.SaseConfig))
	case *sasemodel.NetworkFirewallProfile:
		return rndr.UpdateNetworkFirewallProfile(new.ServiceInfo, 
			old.Config.(*sasemodel.NetworkFirewallProfile), new.Config.(*sasemodel.NetworkFirewallProfile))
	default:
	}
	return nil
}

// DeleteServiceConfig :
func (rndr *Renderer) DeleteServiceConfig(sp *config.SaseServiceConfig) error {
	// Check for service config type
	switch sp.Config.(type) {
	case *sasemodel.SaseConfig:
		return rndr.DeleteSaseConfig(sp.ServiceInfo, sp.Config.(*sasemodel.SaseConfig))
	case *sasemodel.NetworkFirewallProfile:
		return rndr.DeleteNetworkFirewallProfile(sp.ServiceInfo, sp.Config.(*sasemodel.NetworkFirewallProfile))
	default:
	}
	return nil
}

/////////////////////////// Firewall Profiles Related ////////////////

func getNfpDirectionFromSaseConfigDirection(dir sasemodel.SaseConfig_Direction) sasemodel.NetworkFirewallProfile_Direction {

	var nfpDir sasemodel.NetworkFirewallProfile_Direction

	switch dir {
	case sasemodel.SaseConfig_Ingress:
		nfpDir = sasemodel.NetworkFirewallProfile_INGRESS
	case sasemodel.SaseConfig_Egress:
		nfpDir = sasemodel.NetworkFirewallProfile_EGRESS
	}

	// return direction
	return nfpDir
}

func getNfpActionFromSaseAction(act sasemodel.SaseConfig_Action) sasemodel.NetworkFirewallProfile_FirewallRule_Action {

	var nfpAct sasemodel.NetworkFirewallProfile_FirewallRule_Action

	switch act {
	case sasemodel.SaseConfig_DENY:
		nfpAct = sasemodel.NetworkFirewallProfile_FirewallRule_DENY
	case sasemodel.SaseConfig_PERMIT:
		nfpAct = sasemodel.NetworkFirewallProfile_FirewallRule_PERMIT_REFLECT
	}

	// return action
	return nfpAct
}

func getNfpProtocolFromSaseProtocol(proto sasemodel.SaseConfig_Match_Proto) sasemodel.NetworkFirewallProfile_FirewallRule_Proto{

	var nfpProto sasemodel.NetworkFirewallProfile_FirewallRule_Proto

	switch proto {
	case sasemodel.SaseConfig_Match_TCP:
		nfpProto = sasemodel.NetworkFirewallProfile_FirewallRule_TCP
	case sasemodel.SaseConfig_Match_UDP:
		nfpProto = sasemodel.NetworkFirewallProfile_FirewallRule_UDP
	}

	// return Proto
	return nfpProto
}

func getNfpRuleFromSaseConfigMatchAction(m *sasemodel.SaseConfig_Match, a sasemodel.SaseConfig_Action) *sasemodel.NetworkFirewallProfile_FirewallRule {

	// Get the network firewall rule
	rule := &sasemodel.NetworkFirewallProfile_FirewallRule {
		Protocol: getNfpProtocolFromSaseProtocol(m.Protocol),
		SrcProtoPort: 0,
		DstProtoPort: m.ProtocolPort,
		SourceCidr: m.SourceIp,
		DestinationCidr: m.DestinationIp,
		Action: getNfpActionFromSaseAction(a),
	}
	return rule
}

// convertSaseConfigToNetworkFirewallProfile
func convertSaseConfigToNetworkFirewallProfile(sp *sasemodel.SaseConfig) *sasemodel.NetworkFirewallProfile {

	nfp := &sasemodel.NetworkFirewallProfile{
		Name: sp.Name,
		ServiceInstanceName: sp.ServiceInstanceName,
		Direction: getNfpDirectionFromSaseConfigDirection(sp.Direction),
	}

	// Get Nfp Rules
	nfp.Rules = append(nfp.Rules, getNfpRuleFromSaseConfigMatchAction(sp.Match, sp.Action))

	// Get Interface details
	if nfp.Direction == sasemodel.NetworkFirewallProfile_INGRESS {
		nfp.InterfaceName = sp.Match.IngressInterfaceName
	} else if nfp.Direction == sasemodel.NetworkFirewallProfile_EGRESS {
		nfp.InterfaceName = sp.Match.EgressInterfaceName
	}

	return nfp
}
 
// AddSaseConfig :
func (rndr *Renderer) AddSaseConfig(serviceInfo *common.ServiceInfo, sp *sasemodel.SaseConfig, reSync bool) error {
	
	rndr.Log.Infof("Firewall Service: AddSaseConfig: ServiceInfo %v", serviceInfo, "Config: %v", sp)

	// Convert SaseConfig to Network firewall profile
	nfp := convertSaseConfigToNetworkFirewallProfile(sp)
	return rndr.CreateNetworkFirewallProfile(serviceInfo, nfp, reSync)
}

// UpdateSaseConfig :
func (rndr *Renderer) UpdateSaseConfig(serviceInfo *common.ServiceInfo, old, new *sasemodel.SaseConfig) error {
	
	rndr.Log.Infof("Firewall Service: UpdateSaseConfig ServiceInfo %v", serviceInfo, "New Config: %v", new,
		 "Old Config: %v", old)

	oldNfp := convertSaseConfigToNetworkFirewallProfile(old)
	newNfp := convertSaseConfigToNetworkFirewallProfile(new)
	return rndr.UpdateNetworkFirewallProfile(serviceInfo, oldNfp, newNfp)
}

// DeleteSaseConfig :
func (rndr *Renderer) DeleteSaseConfig(serviceInfo *common.ServiceInfo, sp *sasemodel.SaseConfig) error {
	
	rndr.Log.Infof("Firewall Service: DeleteSaseConfig: ServiceInfo %v", serviceInfo, "Config: %v", sp)

	nfp := convertSaseConfigToNetworkFirewallProfile(sp)
	return rndr.DeleteNetworkFirewallProfile(serviceInfo, nfp)
}

// CreateNetworkFirewallProfile adds New Network firewall Profile
func (rndr *Renderer) CreateNetworkFirewallProfile(serviceInfo *common.ServiceInfo, sp *sasemodel.NetworkFirewallProfile, reSync bool) error {
	
	rndr.Log.Infof("Firewall Service: CreateNetworkFirewallProfile: ServiceInfo %v", serviceInfo, "Profile: %v", sp)

	// Render ACL Rules
	vppACL := rndr.renderVppACL(sp)

	rndr.Log.Infof("CreateNetworkFirewallProfile: vppACL: %v", vppACL, "MicroServiceLabel: %s", serviceInfo.GetServicePodLabel())

	// Expect Ingress and Egress Interfaces to be provided as part of configuration
	// Traffic from external entity into the service which firewall is protecting
	aclInterfaces := &vpp_acl.ACL_Interfaces{}
	if sp.Direction == sasemodel.NetworkFirewallProfile_INGRESS {
		aclInterfaces.Ingress = append(aclInterfaces.Ingress, sp.InterfaceName)
	} else {
		// Traffic from internal entity going out. Prevent access to internal entity
		aclInterfaces.Egress = append(aclInterfaces.Egress, sp.InterfaceName)
	}

	vppACL.Interfaces = aclInterfaces

	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_acl.Key(vppACL.Name), vppACL, config.Add)
	}

	// Commit is for local base vpp vswitch
	if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
		rndr.Log.Info(" Firewall Service: CreateNetworkFirewallProfile:  Post txn to local vpp agent",
			"Key: ", vpp_acl.Key(vppACL.Name), "Value: ", vppACL)

		if reSync == true {
			txn := rndr.ResyncTxnFactory()
			txn.Put(vpp_acl.Key(vppACL.Name), vppACL)
		} else {
			txn := rndr.UpdateTxnFactory(fmt.Sprintf("Firewall Service %s", vpp_acl.Key(vppACL.Name)))
			txn.Put(vpp_acl.Key(vppACL.Name), vppACL)
		}
		return nil
	}

	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_acl.Key(vppACL.Name), vppACL, config.Add)

}

// UpdateNetworkFirewallProfile updates existing Network Firewall Profile
func (rndr *Renderer) UpdateNetworkFirewallProfile(serviceInfo *common.ServiceInfo, old, new *sasemodel.NetworkFirewallProfile) error {
	
	rndr.Log.Infof("UpdateNetworkFirewallProfile: %v", new)
	return rndr.CreateNetworkFirewallProfile(serviceInfo, new, false)
}

// DeleteNetworkFirewallProfile deletes an existing network firewall Profile
func (rndr *Renderer) DeleteNetworkFirewallProfile(serviceInfo *common.ServiceInfo, sp *sasemodel.NetworkFirewallProfile) error {

	rndr.Log.Infof("Firewall Service: DeleteNetworkFirewallProfile: ServiceInfo %v", serviceInfo, "Policy: %v", sp)

	// Render ACL Rules
	vppACL := rndr.renderVppACL(sp)

	rndr.Log.Infof("DeleteNetworkFirewallProfile: vppACL: %v", vppACL, "MicroServiceLabel: %s", serviceInfo.GetServicePodLabel())

	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_acl.Key(vppACL.Name), vppACL, config.Delete)
	}

	// Commit is for local base vpp vswitch
	if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
		rndr.Log.Info(" Firewall Service: DeleteNetworkFirewallProfile:  Post txn to local vpp agent",
			"Key: ", vpp_acl.Key(vppACL.Name), "Value: ", vppACL)
		txn := rndr.UpdateTxnFactory(fmt.Sprintf("Firewall Service %s", vpp_acl.Key(vppACL.Name)))
		txn.Delete(vpp_acl.Key(vppACL.Name))
		return nil
	}

	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_acl.Key(vppACL.Name), vppACL, config.Delete)
}

/////////////////////////// Firewall Policies related routines ////////////////

const (
	ipv4AddrAny = "0.0.0.0/0"
	ipv6AddrAny = "::/0"
)

// anyAddrForIPversion returns any addr for the IP version defined by given argument
func anyAddrForIPversion(ip string) string {
	if strings.Contains(ip, ":") {
		return ipv6AddrAny
	}
	return ipv4AddrAny
}

// expandAnyAddr replaces empty string representing any networking in rules by explicit values
func expandAnyAddr(rule *vpp_acl.ACL_Rule) []*vpp_acl.ACL_Rule {
	// both networks are defined, no modification needed
	if rule.IpRule.Ip.SourceNetwork != "" && rule.IpRule.Ip.DestinationNetwork != "" {
		return []*vpp_acl.ACL_Rule{rule}
	}
	// match any version based on the filled network
	if rule.IpRule.Ip.SourceNetwork != "" {
		rule.IpRule.Ip.DestinationNetwork = anyAddrForIPversion(rule.IpRule.Ip.SourceNetwork)
		return []*vpp_acl.ACL_Rule{rule}
	}
	if rule.IpRule.Ip.DestinationNetwork != "" {
		rule.IpRule.Ip.SourceNetwork = anyAddrForIPversion(rule.IpRule.Ip.DestinationNetwork)
		return []*vpp_acl.ACL_Rule{rule}
	}
	// create rules for IPv4 and IPv6 as well
	rule6 := proto.Clone(rule).(*vpp_acl.ACL_Rule)
	rule4 := proto.Clone(rule).(*vpp_acl.ACL_Rule)
	rule4.IpRule.Ip.DestinationNetwork = ipv4AddrAny
	rule4.IpRule.Ip.SourceNetwork = ipv4AddrAny

	rule6.IpRule.Ip.DestinationNetwork = ipv6AddrAny
	rule6.IpRule.Ip.SourceNetwork = ipv6AddrAny

	return []*vpp_acl.ACL_Rule{rule4, rule6}

}

// renderACL renders ContivRuleTable into the equivalent ACL configuration.
func (rndr *Renderer) renderVppACL(profile *sasemodel.NetworkFirewallProfile) *vpp_acl.ACL {
	const maxPortNum = ^uint16(0)
	acl := &vpp_acl.ACL{
		Name: profile.Name,
	}

    // Render ACL Rules
	for _,rule := range profile.Rules {
		aclRule := rndr.renderVppACLRule(rule)
		acl.Rules = append(acl.Rules, expandAnyAddr(aclRule)...)
	}
	return acl
}

func (rndr *Renderer) renderVppACLRule(rule *sasemodel.NetworkFirewallProfile_FirewallRule) *vpp_acl.ACL_Rule {
	const maxPortNum = ^uint16(0)
	// VPP ACL Plugin Rule
	aclRule := &vpp_acl.ACL_Rule{}
	if rule.Action == sasemodel.NetworkFirewallProfile_FirewallRule_PERMIT_REFLECT{
		aclRule.Action = vpp_acl.ACL_Rule_REFLECT
	} else {
		aclRule.Action = vpp_acl.ACL_Rule_DENY
	}

	aclRule.IpRule = &vpp_acl.ACL_Rule_IpRule{}
	aclRule.IpRule.Ip = &vpp_acl.ACL_Rule_IpRule_Ip{}

	// Get Source and Destination Networks
	_, ipv4SrcNet, err := net.ParseCIDR(rule.SourceCidr)
	if err != nil {
			// Invalid or No Src Network provided in config
			ipv4SrcNet = nil
	}
	_, ipv4DstNet, err := net.ParseCIDR(rule.DestinationCidr)
	if err != nil {
			// Invalid or No Dst Network provided in config
			ipv4DstNet = nil
	}

	if ipv4SrcNet!= nil && len(ipv4SrcNet.IP) > 0 {
		aclRule.IpRule.Ip.SourceNetwork = ipv4SrcNet.String()
	}
	if ipv4DstNet != nil && len(ipv4DstNet.IP) > 0 {
		aclRule.IpRule.Ip.DestinationNetwork = ipv4DstNet.String()
	}

	// Protocol TCP
	if rule.Protocol == sasemodel.NetworkFirewallProfile_FirewallRule_TCP {
		aclRule.IpRule.Tcp = &vpp_acl.ACL_Rule_IpRule_Tcp{}
		aclRule.IpRule.Tcp.SourcePortRange = &vpp_acl.ACL_Rule_IpRule_PortRange{}
		aclRule.IpRule.Tcp.SourcePortRange.LowerPort = uint32(rule.SrcProtoPort)
		if rule.SrcProtoPort == 0 {
			aclRule.IpRule.Tcp.SourcePortRange.UpperPort = uint32(maxPortNum)
		} else {
			aclRule.IpRule.Tcp.SourcePortRange.UpperPort = uint32(rule.SrcProtoPort)
		}
		aclRule.IpRule.Tcp.DestinationPortRange = &vpp_acl.ACL_Rule_IpRule_PortRange{}
		aclRule.IpRule.Tcp.DestinationPortRange.LowerPort = uint32(rule.DstProtoPort)
		if rule.DstProtoPort == 0 {
			aclRule.IpRule.Tcp.DestinationPortRange.UpperPort = uint32(maxPortNum)
		} else {
			aclRule.IpRule.Tcp.DestinationPortRange.UpperPort = uint32(rule.DstProtoPort)
		}
	}

	// Protocol UDP
	if rule.Protocol == sasemodel.NetworkFirewallProfile_FirewallRule_UDP {
		aclRule.IpRule.Udp = &vpp_acl.ACL_Rule_IpRule_Udp{}
		aclRule.IpRule.Udp.SourcePortRange = &vpp_acl.ACL_Rule_IpRule_PortRange{}
		aclRule.IpRule.Udp.SourcePortRange.LowerPort = uint32(rule.SrcProtoPort)
		if rule.SrcProtoPort == 0 {
			aclRule.IpRule.Udp.SourcePortRange.UpperPort = uint32(maxPortNum)
		} else {
			aclRule.IpRule.Udp.SourcePortRange.UpperPort = uint32(rule.SrcProtoPort)
		}
		aclRule.IpRule.Udp.DestinationPortRange = &vpp_acl.ACL_Rule_IpRule_PortRange{}
		aclRule.IpRule.Udp.DestinationPortRange.LowerPort = uint32(rule.DstProtoPort)
		if rule.DstProtoPort == 0 {
			aclRule.IpRule.Udp.DestinationPortRange.UpperPort = uint32(maxPortNum)
		} else {
			aclRule.IpRule.Udp.DestinationPortRange.UpperPort = uint32(rule.DstProtoPort)
		}
	}

	// Protocol ICMP

	return aclRule
}