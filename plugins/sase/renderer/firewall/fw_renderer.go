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
	"errors"
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
	"github.com/ligato/cn-infra/logging"
	vpp_acl "github.com/ligato/vpp-agent/api/models/vpp/acl"
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
func (rndr *Renderer) AddServiceConfig(sp *config.SaseServiceConfig) error {

	// Check for service config type
	switch sp.Config.(type) {
	case *sasemodel.SaseConfig:
		return rndr.AddPolicy(sp.ServiceInfo, sp.Config.(*sasemodel.SaseConfig))
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
	// Check for service config type
	switch sp.Config.(type) {
	case *sasemodel.SaseConfig:
		return rndr.DeletePolicy(sp.ServiceInfo, sp.Config.(*sasemodel.SaseConfig))
	default:
	}
	return nil
}

// AddPolicy adds firewall related policies
func (rndr *Renderer) AddPolicy(serviceInfo *common.ServiceInfo, sp *sasemodel.SaseConfig) error {
	rndr.Log.Infof("Firewall Service: AddPolicy: ")

	// convert Sase Service Policy to native firewall representation
	fwRule, err := convertSasePolicyToFirewallRule(sp)
	if err != nil {
		return err
	}

	rndr.Log.Infof("AddPolicy: fwRule: %v", fwRule)

	// Render ACL Rules
	vppACL := rndr.renderVppACLRule(sp.Name, fwRule)

	// Render ACL Ingress/Egress Interfaces
	vppACL.Interfaces = rndr.renderVppACLInterfaces(serviceInfo.Pod, sp.Direction)

	rndr.Log.Infof("AddPolicy: vppACL: %v", vppACL)
	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_acl.Key(vppACL.Name), vppACL, config.Add)
}

// UpdatePolicy updates exiting firewall  related policies
func (rndr *Renderer) UpdatePolicy(serviceInfo *common.ServiceInfo, old, new *sasemodel.SaseConfig) error {
	return nil
}

// DeletePolicy deletes an existing firewall  policy
func (rndr *Renderer) DeletePolicy(serviceInfo *common.ServiceInfo, sp *sasemodel.SaseConfig) error {

	rndr.Log.Infof("Firewall Service: DeletePolicy: ")
	// convert Sase Service Policy to native firewall representation
	fwRule, err := convertSasePolicyToFirewallRule(sp)
	if err != nil {
		return err
	}

	vppACL := rndr.renderVppACLRule(sp.Name, fwRule)
	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_acl.Key(vppACL.Name), vppACL, config.Delete)
}

/////////////////////////// Firewall Policies related routines ////////////////

// ConvertSasePolicyToFirewallRule: convert SaseServicePolicy to firewall policy
func convertSasePolicyToFirewallRule(sp *sasemodel.SaseConfig) (*FirewallRule, error) {

	// Get Source and Destination Networks
	_, ipv4SrcNet, _ := net.ParseCIDR(sp.Match.SourceIp)
	_, ipv4DstNet, _ := net.ParseCIDR(sp.Match.DestinationIp)

	// Check for supported actions for firewall service
	if sp.Action != sasemodel.SaseConfig_PERMIT &&
		sp.Action != sasemodel.SaseConfig_DENY {
		return nil, errors.New("Error: Invalid Firewall Action")
	}

	// Firewall rule in native form that can be consumed by renderer
	rule := &FirewallRule{
		Action:      sp.Action,
		Protocol:    sp.Match.Protocol,
		SrcNetwork:  ipv4SrcNet,
		DestNetwork: ipv4DstNet,
		//SrcPort:     1004,
		DestPort: uint16(sp.Match.Port),
	}
	return rule, nil
}

const (
	// ACLNamePrefix is used to tag ACLs created for the implementation of K8s policies.
	ACLNamePrefix = "sase-firewall-"

	// ReflectiveACLName is the name of the *reflective* ACL (full name prefixed with
	// ACLNamePrefix). Reflective ACL is used to allow responses of accepted sessions
	// regardless of installed policies on the way back.
	ReflectiveACLName = "REFLECTION"

	ipv4AddrAny = "0.0.0.0/0"
	ipv6AddrAny = "::/0"
)

// FirewallRule is an n-tuple with the most basic policy rule
type FirewallRule struct {
	// Action to perform when traffic matches.
	Action sasemodel.SaseConfig_Action

	// L3
	SrcNetwork  *net.IPNet // empty = match all
	DestNetwork *net.IPNet // empty = match all

	// L4
	Protocol sasemodel.SaseConfig_Match_Proto
	SrcPort  uint16 // 0 = match all
	DestPort uint16 // 0 = match all
}

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

// Render Interfaces for ACL Rules depending on Direction specified in the Policy rule
func (rndr *Renderer) renderVppACLInterfaces(pod *common.PodInfo, dir sasemodel.SaseConfig_Direction) *vpp_acl.ACL_Interfaces {

	aclInterfaces := &vpp_acl.ACL_Interfaces{}

	// Traffic from external entity into the service which firewall is protecting
	if dir == sasemodel.SaseConfig_Ingress {
		for _, intf := range pod.Interfaces {
			if intf.IsIngress == false {
				aclInterfaces.Ingress = append(aclInterfaces.Ingress, intf.InternalName)
			}
		}
	} else {
		// Traffic from internal entity going out. Prevent access to internal entity
		for _, intf := range pod.Interfaces {
			if intf.IsIngress == true {
				aclInterfaces.Egress = append(aclInterfaces.Ingress, intf.InternalName)
			}
		}
	}
	return aclInterfaces
}

// renderACL renders ContivRuleTable into the equivalent ACL configuration.
func (rndr *Renderer) renderVppACLRule(name string, rule *FirewallRule) *vpp_acl.ACL {
	const maxPortNum = ^uint16(0)
	acl := &vpp_acl.ACL{
		Name: name,
	}

	// VPP ACL Plugin Rule
	// VENKAT: Note Reflective ACL? Use case
	aclRule := &vpp_acl.ACL_Rule{}
	if rule.Action == sasemodel.SaseConfig_DENY {
		aclRule.Action = vpp_acl.ACL_Rule_DENY
	} else {
		aclRule.Action = vpp_acl.ACL_Rule_PERMIT
	}

	aclRule.IpRule = &vpp_acl.ACL_Rule_IpRule{}
	aclRule.IpRule.Ip = &vpp_acl.ACL_Rule_IpRule_Ip{}
	if len(rule.SrcNetwork.IP) > 0 {
		aclRule.IpRule.Ip.SourceNetwork = rule.SrcNetwork.String()
	}
	if len(rule.DestNetwork.IP) > 0 {
		aclRule.IpRule.Ip.DestinationNetwork = rule.DestNetwork.String()
	}

	// Protocol TCP
	if rule.Protocol == sasemodel.SaseConfig_Match_TCP {
		aclRule.IpRule.Tcp = &vpp_acl.ACL_Rule_IpRule_Tcp{}
		aclRule.IpRule.Tcp.SourcePortRange = &vpp_acl.ACL_Rule_IpRule_PortRange{}
		aclRule.IpRule.Tcp.SourcePortRange.LowerPort = uint32(rule.SrcPort)
		if rule.SrcPort == 0 {
			aclRule.IpRule.Tcp.SourcePortRange.UpperPort = uint32(maxPortNum)
		} else {
			aclRule.IpRule.Tcp.SourcePortRange.UpperPort = uint32(rule.SrcPort)
		}
		aclRule.IpRule.Tcp.DestinationPortRange = &vpp_acl.ACL_Rule_IpRule_PortRange{}
		aclRule.IpRule.Tcp.DestinationPortRange.LowerPort = uint32(rule.DestPort)
		if rule.DestPort == 0 {
			aclRule.IpRule.Tcp.DestinationPortRange.UpperPort = uint32(maxPortNum)
		} else {
			aclRule.IpRule.Tcp.DestinationPortRange.UpperPort = uint32(rule.DestPort)
		}
	}

	// Protocol UDP
	if rule.Protocol == sasemodel.SaseConfig_Match_UDP {
		aclRule.IpRule.Udp = &vpp_acl.ACL_Rule_IpRule_Udp{}
		aclRule.IpRule.Udp.SourcePortRange = &vpp_acl.ACL_Rule_IpRule_PortRange{}
		aclRule.IpRule.Udp.SourcePortRange.LowerPort = uint32(rule.SrcPort)
		if rule.SrcPort == 0 {
			aclRule.IpRule.Udp.SourcePortRange.UpperPort = uint32(maxPortNum)
		} else {
			aclRule.IpRule.Udp.SourcePortRange.UpperPort = uint32(rule.SrcPort)
		}
		aclRule.IpRule.Udp.DestinationPortRange = &vpp_acl.ACL_Rule_IpRule_PortRange{}
		aclRule.IpRule.Udp.DestinationPortRange.LowerPort = uint32(rule.DestPort)
		if rule.DestPort == 0 {
			aclRule.IpRule.Udp.DestinationPortRange.UpperPort = uint32(maxPortNum)
		} else {
			aclRule.IpRule.Udp.DestinationPortRange.UpperPort = uint32(rule.DestPort)
		}
	}
	acl.Rules = append(acl.Rules, expandAnyAddr(aclRule)...)

	return acl
}

// Commit proceeds with the rendering to the local vpp dataplane instead of posting to
// etcd for re-direction.
func (rndr *Renderer) Commit(acl *vpp_acl.ACL) error {

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("commit acl %s", acl.Name))
	txn.Put(vpp_acl.Key(acl.Name), acl)

	return nil
}
