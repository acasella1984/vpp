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

package firewall

import (
	"github.com/contiv/vpp/plugins/policy/renderer"
	"github.com/contiv/vpp/plugins/policy/renderer/cache"
	"github.com/gogo/protobuf/proto"
	vpp_acl "github.com/ligato/vpp-agent/api/models/vpp/acl"
)

// Commit proceeds with the rendering. A minimalistic set of changes is
// calculated using RendererCache and applied as one transaction via the
// localclient.
func (art *RendererTxn) Commit() error {
	if art.resync {
		return art.commitResync()
	}

	var (
		globalTable      *cache.ContivRuleTable
		hasReflectiveACL bool
	)

	if art.renderer.cache.GetGlobalTable().NumOfRules != 0 ||
		len(art.renderer.cache.GetIsolatedPods()) > 0 {
		hasReflectiveACL = true
	}

	// Get the minimalistic diff to be rendered.
	changes := art.cacheTxn.GetChanges()
	if len(changes) == 0 {
		// Still need to commit the configuration updates from the transaction.
		return art.cacheTxn.Commit()
	}
	txn := art.renderer.UpdateTxnFactory()

	// First render local tables.
	for _, change := range changes {
		if change.Table.Type == cache.Global {
			// Reconfigure global table after the local ones.
			globalTable = change.Table
			continue
		}
		if len(change.PreviousPods) == 0 {
			// New ACL
			acl := art.renderACL(change.Table, false)
			txn.Put(vpp_acl.Key(acl.Name), acl)
		} else if len(change.Table.Pods) != 0 {
			// Changed interfaces
			aclPrivCopy := proto.Clone(change.Table.Private.(*vpp_acl.ACL))
			acl := aclPrivCopy.(*vpp_acl.ACL)
			acl.Interfaces = art.renderInterfaces(change.Table.Pods, false)
			txn.Put(vpp_acl.Key(acl.Name), acl)
		} else {
			// Removed ACL
			acl := change.Table.Private.(*vpp_acl.ACL)
			txn.Delete(vpp_acl.Key(acl.Name))
		}
	}

	// Render the global table.
	var gtAddedOrDeleted bool // will be true if global table is being added / removed (not updated)
	if globalTable != nil {
		globalACL := art.renderACL(globalTable, false)
		if globalTable.NumOfRules == 0 {
			// Remove empty global table.
			txn.Delete(vpp_acl.Key(globalACL.Name))
			gtAddedOrDeleted = true
		} else {
			// Update content of the global table.
			globalACL.Interfaces.Egress = art.getNodeOutputInterfaces()
			txn.Put(vpp_acl.Key(globalACL.Name), globalACL)
			if art.renderer.cache.GetGlobalTable().NumOfRules == 0 {
				gtAddedOrDeleted = true
			}
		}
	}

	// Render the reflective ACL
	if gtAddedOrDeleted || !art.cacheTxn.GetIsolatedPods().Equals(art.renderer.cache.GetIsolatedPods()) {
		reflectiveACL := art.reflectiveACL()
		if len(reflectiveACL.Interfaces.Ingress) == 0 {
			if hasReflectiveACL {
				txn.Delete(vpp_acl.Key(reflectiveACL.Name))
			}
		} else {
			txn.Put(vpp_acl.Key(reflectiveACL.Name), reflectiveACL)
		}
	}

	// Save changes into the cache.
	return art.cacheTxn.Commit()
}

// renderACL renders ContivRuleTable into the equivalent ACL configuration.
func (art *RendererTxn) renderACL(table *cache.ContivRuleTable, isReflectiveACL bool) *vpp_acl.ACL {
	const maxPortNum = ^uint16(0)
	acl := &vpp_acl.ACL{}
	if isReflectiveACL {
		acl.Name = ACLNamePrefix + ReflectiveACLName
	} else {
		acl.Name = ACLNamePrefix + table.GetID()
	}
	acl.Interfaces = art.renderInterfaces(table.Pods, isReflectiveACL)

	for i := 0; i < table.NumOfRules; i++ {
		rule := table.Rules[i]
		aclRule := &vpp_acl.ACL_Rule{}
		if rule.Action == renderer.ActionDeny {
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
		if rule.Protocol == renderer.TCP {
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
		if rule.Protocol == renderer.UDP {
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
	}

	table.Private = acl
	return acl
}
