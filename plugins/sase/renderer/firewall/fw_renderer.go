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
	"fmt"
	"net"
	"strings"

	"github.com/gogo/protobuf/proto"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
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
	Config           *config.Config
	ContivConf       contivconf.API
	IPAM             ipam.API
	IPNet            ipnet.API
	UpdateTxnFactory func(change string) (txn controller.UpdateOperations)
	ResyncTxnFactory func() (txn controller.ResyncOperations)
	Stats            statscollector.API /* used for exporting the statistics */
}

// Init initializes the renderer.
func (rndr *Renderer) Init() error {
	if rndr.Config == nil {
		rndr.Config = config.DefaultFirewallConfig()
	}
	return nil
}

// AfterInit starts asynchronous NAT session cleanup.
func (rndr *Renderer) AfterInit() error {
	return nil
}

// AddPolicy adds firewall related policies
func (rndr *Renderer) AddPolicy(sp *renderer.SaseServicePolicy) error {
	rndr.Log.Infof("Firewall Service: AddPolicy: ")
	// convert Sase Service Policy to native firewall representation
	fwRule := convertSasePolicyToFirewallRule(sp)
	rndr.Log.Infof("AddPolicy: fwRule: %v", fwRule)
	vppACL := rndr.renderVppACL(fwRule, true)
	rndr.Log.Infof("AddPolicy: vppACL: %v", vppACL)
	return rndr.Commit(vppACL)
}

// UpdatePolicy updates exiting firewall  related policies
func (rndr *Renderer) UpdatePolicy(old, new *renderer.SaseServicePolicy) error {
	return nil
}

// DeletePolicy deletes an existing firewall  policy
func (rndr *Renderer) DeletePolicy(sp *renderer.SaseServicePolicy) error {
	return nil
}

/////////////////////////// Firewall Rule related routines ////////////////

// ConvertSasePolicyToFirewallRule: convert SaseServicePolicy to firewall policy
func convertSasePolicyToFirewallRule(sp *renderer.SaseServicePolicy) *FirewallRule {

	_, ipv4SrcNet, _ := net.ParseCIDR("192.0.2.1/24")
	_, ipv4DstNet, _ := net.ParseCIDR("100.0.2.1/24")

	rule := &FirewallRule{
		Action:      ActionDeny,
		Protocol:    TCP,
		SrcNetwork:  ipv4SrcNet,
		DestNetwork: ipv4DstNet,
		SrcPort:     1004,
		DestPort:    8080,
	}
	return rule
}

// ActionType is either DENY or PERMIT.
type ActionType int

const (
	// ActionDeny tells the policy engine to block the matching traffic.
	ActionDeny ActionType = iota
	// ActionPermit tells the policy engine to block the matching traffic.
	ActionPermit
)

// String converts ActionType into a human-readable string.
func (at ActionType) String() string {
	switch at {
	case ActionDeny:
		return "DENY"
	case ActionPermit:
		return "PERMIT"
	}
	return "INVALID"
}

// ProtocolType is either TCP or UDP or OTHER.
type ProtocolType int

const (
	// TCP protocol.
	TCP ProtocolType = iota
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
	Action ActionType

	// L3
	SrcNetwork  *net.IPNet // empty = match all
	DestNetwork *net.IPNet // empty = match all

	// L4
	Protocol ProtocolType
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

// renderACL renders ContivRuleTable into the equivalent ACL configuration.
func (rndr *Renderer) renderVppACL(rule *FirewallRule, isReflectiveACL bool) *vpp_acl.ACL {
	const maxPortNum = ^uint16(0)
	acl := &vpp_acl.ACL{}
	if isReflectiveACL {
		acl.Name = ACLNamePrefix + ReflectiveACLName
	} else {
		//acl.Name = ACLNamePrefix + table.GetID()
	}

	// VENKAT:: How do we get these interfaces???
	// TBD
	//acl.Interfaces = art.renderInterfaces(table.Pods, isReflectiveACL)

	// VPP ACL Plugin Rule
	aclRule := &vpp_acl.ACL_Rule{}
	if rule.Action == ActionDeny {
		aclRule.Action = vpp_acl.ACL_Rule_DENY
	} else if isReflectiveACL {
		aclRule.Action = vpp_acl.ACL_Rule_REFLECT
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
	if rule.Protocol == TCP {
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
	if rule.Protocol == UDP {
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

// Commit proceeds with the rendering. A minimalistic set of changes is
// calculated using RendererCache and applied as one transaction via the
// localclient.
func (rndr *Renderer) Commit(acl *vpp_acl.ACL) error {
	txn := rndr.UpdateTxnFactory(fmt.Sprintf("commit acl %s", acl.Name))
	txn.Put(vpp_acl.Key(acl.Name), acl)
	return nil
}
