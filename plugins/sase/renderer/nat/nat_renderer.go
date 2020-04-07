/*
 * // Copyright (c) 2018 Cisco and/or its affiliates.
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

package natservice

import (
	"fmt"
	"go.ligato.io/cn-infra/v2/logging"
	"net"

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

	vpp_nat "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/nat"
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
		rndr.Config = config.DefaultNatConfig()
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
		rndr.DeletePolicy(sp.ServiceInfo, sp.Config.(*sasemodel.SaseConfig))
	default:
	}
	return nil
}

// AddPolicy adds NAT related policies
func (rndr *Renderer) AddPolicy(serviceInfo *common.ServiceInfo, sp *sasemodel.SaseConfig, reSync bool) error {

	// Source NAT configuration
	if sp.Action == sasemodel.SaseConfig_SNAT {

		// Ingress NAT Interface
		nat44IngressIntf := &vpp_nat.Nat44Interface{
			Name:          sp.Match.IngressInterfaceName,
			NatInside:     true,
			OutputFeature: true,
		}

		// Test Purpose
		if rndr.MockTest {
			return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_nat.Nat44InterfaceKey(nat44IngressIntf.Name),
				nat44IngressIntf, config.Add)
		}

		// Txn is for local base VPP CNF
		if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
			rndr.Log.Info(" AddPolicy NAT Inside Interface: Post txn to local vpp agent",
				"Key: ", vpp_nat.Nat44InterfaceKey(nat44IngressIntf.Name), "Value: ", nat44IngressIntf)

			if reSync == true {
				txn := rndr.ResyncTxnFactory()
				txn.Put(vpp_nat.Nat44InterfaceKey(nat44IngressIntf.Name), nat44IngressIntf)
			} else {
				txn := rndr.UpdateTxnFactory(fmt.Sprintf("AddPolicy NAT Inside Interface %s", vpp_nat.Nat44InterfaceKey(nat44IngressIntf.Name)))
				txn.Put(vpp_nat.Nat44InterfaceKey(nat44IngressIntf.Name), nat44IngressIntf)
			}
		} else {
			// Txn is for remote VPP based CNF
			renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_nat.Nat44InterfaceKey(nat44IngressIntf.Name),
				nat44IngressIntf, config.Add)
		}

		// Egress NAT Interface
		nat44EgressIntf := &vpp_nat.Nat44Interface{
			Name:          sp.Match.EgressInterfaceName,
			NatOutside:    true,
			OutputFeature: true,
		}

		// Test Purpose
		if rndr.MockTest {
			return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_nat.Nat44InterfaceKey(nat44EgressIntf.Name),
				nat44EgressIntf, config.Add)
		}

		// Txn is for local base VPP CNF
		if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
			rndr.Log.Info(" AddPolicy NAT Outside Interface: Post txn to local vpp agent",
				"Key: ", vpp_nat.Nat44InterfaceKey(nat44EgressIntf.Name), "Value: ", nat44EgressIntf)
			if reSync == true {
				txn := rndr.ResyncTxnFactory()
				txn.Put(vpp_nat.Nat44InterfaceKey(nat44EgressIntf.Name), nat44EgressIntf)
			} else {
				txn := rndr.UpdateTxnFactory(fmt.Sprintf("AddPolicy NAT Outside Interface %s", vpp_nat.Nat44InterfaceKey(nat44EgressIntf.Name)))
				txn.Put(vpp_nat.Nat44InterfaceKey(nat44EgressIntf.Name), nat44EgressIntf)
			}

		} else {
			// Txn is for remote VPP based CNF
			renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_nat.Nat44InterfaceKey(nat44EgressIntf.Name),
				nat44EgressIntf, config.Add)
		}

		// Add Outside Interface IP Address to NAT Address Pool
		nat44EgressAddress := &vpp_nat.Nat44AddressPool{
			VrfId:   0,
			FirstIp: sp.Match.DestinationIp,
			LastIp:  sp.Match.DestinationIp,
		}

		// Test Purpose
		if rndr.MockTest {
			return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_nat.Nat44AddressPoolKey(nat44EgressAddress.VrfId, nat44EgressAddress.FirstIp, nat44EgressAddress.LastIp),
				nat44EgressAddress, config.Add)
		}

		// Txn is for local base VPP CNF
		if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
			rndr.Log.Info(" AddPolicy NAT AddressPool: Post txn to local vpp agent",
				"Key: ", vpp_nat.Nat44AddressPoolKey(nat44EgressAddress.VrfId, nat44EgressAddress.FirstIp, nat44EgressAddress.LastIp),
				"Value: ", nat44EgressAddress)
			if reSync == true {
				txn := rndr.ResyncTxnFactory()
				txn.Put(vpp_nat.Nat44AddressPoolKey(nat44EgressAddress.VrfId, nat44EgressAddress.FirstIp, nat44EgressAddress.LastIp),
					nat44EgressAddress)
			} else {
				txn := rndr.UpdateTxnFactory(fmt.Sprintf("AddPolicy NAT AddressPool %s", vpp_nat.Nat44AddressPoolKey(nat44EgressAddress.VrfId, nat44EgressAddress.FirstIp, nat44EgressAddress.LastIp)))
				txn.Put(vpp_nat.Nat44AddressPoolKey(nat44EgressAddress.VrfId, nat44EgressAddress.FirstIp, nat44EgressAddress.LastIp),
					nat44EgressAddress)
			}

		} else {
			// Txn is for remote VPP based CNF
			renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_nat.Nat44AddressPoolKey(nat44EgressAddress.VrfId, nat44EgressAddress.FirstIp, nat44EgressAddress.LastIp),
				nat44EgressAddress, config.Add)
		}
	}
	return nil

}

// DeletePolicy deletes NAT related policies
func (rndr *Renderer) DeletePolicy(serviceInfo *common.ServiceInfo, sp *sasemodel.SaseConfig) error {

	// Source NAT configuration
	if sp.Action == sasemodel.SaseConfig_SNAT {

		// Ingress NAT Interface
		nat44IngressIntf := &vpp_nat.Nat44Interface{
			Name:          sp.Match.IngressInterfaceName,
			NatInside:     true,
			OutputFeature: true,
		}

		// Test Purpose
		if rndr.MockTest {
			return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_nat.Nat44InterfaceKey(nat44IngressIntf.Name),
				nat44IngressIntf, config.Add)
		}

		// Txn is for local base VPP CNF
		if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
			rndr.Log.Info(" DeletePolicy NAT Inside Interface: Post txn to local vpp agent",
				"Key: ", vpp_nat.Nat44InterfaceKey(nat44IngressIntf.Name), "Value: ", nat44IngressIntf)
			txn := rndr.UpdateTxnFactory(fmt.Sprintf("DeletePolicy NAT Inside Interface %s", vpp_nat.Nat44InterfaceKey(nat44IngressIntf.Name)))
			txn.Delete(vpp_nat.Nat44InterfaceKey(nat44IngressIntf.Name))
		} else {
			// Txn is for remote VPP based CNF
			renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_nat.Nat44InterfaceKey(nat44IngressIntf.Name),
				nat44IngressIntf, config.Delete)
		}

		// Egress NAT Interface
		nat44EgressIntf := &vpp_nat.Nat44Interface{
			Name:          sp.Match.EgressInterfaceName,
			NatOutside:    true,
			OutputFeature: true,
		}

		// Test Purpose
		if rndr.MockTest {
			return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_nat.Nat44InterfaceKey(nat44EgressIntf.Name),
				nat44EgressIntf, config.Delete)
		}

		// Txn is for local base VPP CNF
		if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
			rndr.Log.Info(" DeletePolicy NAT Outside Interface: Post txn to local vpp agent",
				"Key: ", vpp_nat.Nat44InterfaceKey(nat44EgressIntf.Name), "Value: ", nat44EgressIntf)
			txn := rndr.UpdateTxnFactory(fmt.Sprintf("DeletePolicy NAT Outside Interface %s", vpp_nat.Nat44InterfaceKey(nat44EgressIntf.Name)))
			txn.Delete(vpp_nat.Nat44InterfaceKey(nat44EgressIntf.Name))
		} else {
			// Txn is for remote VPP based CNF
			renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_nat.Nat44InterfaceKey(nat44EgressIntf.Name),
				nat44EgressIntf, config.Delete)
		}

		// Outside Interface IP Address to NAT Address Pool
		nat44EgressAddress := &vpp_nat.Nat44AddressPool{
			VrfId:   0,
			FirstIp: sp.Match.DestinationIp,
			LastIp:  sp.Match.DestinationIp,
		}

		// Test Purpose
		if rndr.MockTest {
			return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_nat.Nat44AddressPoolKey(nat44EgressAddress.VrfId, nat44EgressAddress.FirstIp, nat44EgressAddress.LastIp),
				nat44EgressAddress, config.Delete)
		}

		// Txn is for local base VPP CNF
		if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
			rndr.Log.Info(" DelPolicy NAT AddressPool: Post txn to local vpp agent",
				"Key: ", vpp_nat.Nat44AddressPoolKey(nat44EgressAddress.VrfId, nat44EgressAddress.FirstIp, nat44EgressAddress.LastIp),
				"Value: ", nat44EgressAddress)
			txn := rndr.UpdateTxnFactory(fmt.Sprintf("DelPolicy NAT AddressPool %s", vpp_nat.Nat44AddressPoolKey(nat44EgressAddress.VrfId, nat44EgressAddress.FirstIp, nat44EgressAddress.LastIp)))
			txn.Delete(vpp_nat.Nat44AddressPoolKey(nat44EgressAddress.VrfId, nat44EgressAddress.FirstIp, nat44EgressAddress.LastIp))

		} else {
			// Txn is for remote VPP based CNF
			renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_nat.Nat44AddressPoolKey(nat44EgressAddress.VrfId, nat44EgressAddress.FirstIp, nat44EgressAddress.LastIp),
				nat44EgressAddress, config.Delete)
		}
	}
	return nil
}

/*
// AddPolicy adds route related policies
func (rndr *Renderer) AddPolicy(serviceInfo *common.ServiceInfo, sp *sasemodel.SaseConfig) error {
	var key string
	var vppNAT proto.Message
	// convert Sase Service Policy to native NAT representation
	natRule := convertSasePolicyToNatRule(serviceInfo, sp)
	if natRule.Type == SourceNAT {
		rndr.Log.Infof("AddPolicy: SNAT NatRule: %v", natRule.SNat)
		vppNAT = rndr.renderVppSNAT(natRule)
		key = vpp_nat.GlobalNAT44Key()
	} else if natRule.Type == DestinationNAT {
		rndr.Log.Infof("AddPolicy: DNAT NatRule: %v", natRule.DNat)
		vppNAT = rndr.renderVppDNAT(sp.Name, natRule)
		key = vpp_nat.DNAT44Key(natRule.DNat.Key)
	}

	rndr.Log.Infof("AddPolicy: vppNAT: %v", vppNAT, "type: %d", natRule.Type)

	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), key, vppNAT, config.Add)
	}

	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), key, vppNAT, config.Add)
}

// UpdatePolicy updates exiting route related policies
func (rndr *Renderer) UpdatePolicy(serviceInfo *common.ServiceInfo, old, new *sasemodel.SaseConfig) error {
	return nil
}

// DeletePolicy deletes an existing route policy
func (rndr *Renderer) DeletePolicy(serviceInfo *common.ServiceInfo, sp *sasemodel.SaseConfig) error {
	var key string
	var vppNAT proto.Message
	rndr.Log.Info("NAT Service: DeletePolicy: ")
	// convert Sase Service Policy to native NAT representation
	natRule := convertSasePolicyToNatRule(serviceInfo, sp)
	rndr.Log.Infof("DeletePolicy: NatRule: %v", natRule)
	if natRule.Type == SourceNAT {
		vppNAT = rndr.renderVppSNAT(natRule)
		key = vpp_nat.GlobalNAT44Key()
	} else if natRule.Type == DestinationNAT {
		vppNAT = rndr.renderVppDNAT(sp.Name, natRule)
		key = vpp_nat.DNAT44Key(natRule.DNat.Key)
	}

	rndr.Log.Infof("DeletePolicy: vppNAT: %v", vppNAT, "type: %d", natRule.Type)
	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), key, vppNAT, config.Delete)
	}
	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), key, vppNAT, config.Delete)
}

// convertSasePolicyToNatRule: convert SaseServicePolicy to firewall policy
func convertSasePolicyToNatRule(serviceInfo *common.ServiceInfo, sp *sasemodel.SaseConfig) *NATRule {

	// Convert Sase Policy into native SNAT or DNAT rule
	rule := &NATRule{}
	// SNAT
	if sp.GetAction() == sasemodel.SaseConfig_SNAT {
		snatRule := &SNATConfig{}

		// Commit is for local base vpp vswitch
		if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
			snatRule.LocalInterfaces = append(snatRule.LocalInterfaces,
				config.Interface{
					Name:    sp.Match.SrcInterfaceName,
					IsLocal: true})
			snatRule.ExternalInterface = append(snatRule.ExternalInterface,
				config.Interface{
					Name:    sp.Match.DstInterfaceName,
					IsLocal: true})
		} else {
			for _, intf := range serviceInfo.Pod.Interfaces {
				if intf.IsIngress == true {
					// Inside Interface
					snatRule.LocalInterfaces = append(snatRule.LocalInterfaces,
						config.Interface{
							Name:    intf.InternalName,
							IsLocal: true})
					snatRule.LocalSubnetList = append(snatRule.LocalSubnetList,
						config.Subnets{
							Subnet: intf.IPAddress})
				} else {
					// Outside Interface
					snatRule.ExternalInterface = append(snatRule.ExternalInterface,
						config.Interface{
							Name:    intf.InternalName,
							IsLocal: false})
					snatRule.ExternalIP = append(snatRule.ExternalIP,
						config.Subnets{
							Subnet: intf.IPAddress})
				}
			}
		}
		// Assign SNAT rule to NATRule
		rule.Type = SourceNAT
		rule.SNat = snatRule
	} else {
		// DNAT: TBD
	}
	return rule
} */

// NatType :
type NatType int

const (
	// None : No Nat configuration
	None NatType = iota

	// SourceNAT :
	SourceNAT

	// DestinationNAT :
	DestinationNAT
)

// NATRule :
type NATRule struct {
	Type NatType
	SNat *SNATConfig
	DNat *DNATConfig
}

// SNATConfig : SNAT allows inside hosts with private IP Addresses
// to connect to outside Public network
type SNATConfig struct {
	// Local Private Subnets that needs NAT
	LocalSubnetList []config.Subnets
	// Public IP
	ExternalIP []config.Subnets
	// Local Interface List
	LocalInterfaces   []config.Interface
	ExternalInterface []config.Interface
}

// EndPoint : Represents an endpoint idenified by IP/Port/Protocol
type EndPoint struct {
	IPAddr   net.IP
	Protocol config.ProtocolType
	AppPort  uint32
	Intf     config.Interface
}

// DNATConfig : DNAT allows Outside hosts to connect to inside hosts with private IP Address
// Local private IP Address could represent an HTTPS server or application server on specific port
// (Local Resource: {IP, Port, Protocol})
type DNATConfig struct {
	Key                string
	LocalEndPoints     []EndPoint
	ExternalEndPoint   EndPoint
	ExternalInterfaces config.Interface
	TwiceNatEnabled    bool
}

// Ligato VPP Nat Plugin
// https://ligato-docs.readthedocs.io/en/latest/user-guide/articles/NAT-plugin/
// - NAT Global Config
// - DNAT44 config

// renderVppSNAT :: Renders VPP Global Nat Config
func (rndr *Renderer) renderVppSNAT(natRule *NATRule) *vpp_nat.Nat44Global {
	globalNat := &vpp_nat.Nat44Global{
		Forwarding: true, // By Default forwarding enabled. VENKAT: Note
		VirtualReassembly: &vpp_nat.VirtualReassembly{
			Timeout:       10,
			DropFragments: true,
		},
		NatInterfaces: getSNATInterfaceList(append(natRule.SNat.LocalInterfaces, natRule.SNat.ExternalInterface...)),
	}

	// Get NAT Local Address Pool
	for _, addr := range natRule.SNat.LocalSubnetList {
		globalNat.AddressPool = append(globalNat.AddressPool, getSNATAddress(addr))
	}

	// Get NAT global address Pool
	for _, addr := range natRule.SNat.ExternalIP {
		globalNat.AddressPool = append(globalNat.AddressPool, getSNATAddress(addr))
	}

	return globalNat
}

// renderVppSNAT :: Renders VPP DNAT Config
func (rndr *Renderer) renderVppDNAT(key string, natRule *NATRule) *vpp_nat.DNat44 {
	dnatCfg := &vpp_nat.DNat44{}
	return dnatCfg
}

func getSNATInterfaceList(natInterfaceList []config.Interface) []*vpp_nat.Nat44Global_Interface {
	var vppNatInterfaces []*vpp_nat.Nat44Global_Interface
	for _, intf := range natInterfaceList {
		vppNatInterfaces = append(vppNatInterfaces, getSNATInterface(intf))
	}
	return vppNatInterfaces
}

func getSNATInterface(natIntf config.Interface) *vpp_nat.Nat44Global_Interface {
	// Get VPP Interface
	natInterface := &vpp_nat.Nat44Global_Interface{
		Name:          natIntf.Name,
		IsInside:      natIntf.IsLocal,
		OutputFeature: natIntf.TwiceNat,
	}
	return natInterface
}

func getSNATAddress(address config.Subnets) *vpp_nat.Nat44Global_Address {

	// Get VPP  Address
	vppAddress := &vpp_nat.Nat44Global_Address{
		Address: address.Subnet,
		VrfId:   address.Vrf,
		//TwiceNat:
	}
	return vppAddress
}

func getNatType(t sasemodel.SaseConfig_Action) NatType {

	// DNAT
	if t == sasemodel.SaseConfig_DNAT {
		return DestinationNAT
	}

	// SNAT
	return SourceNAT
}
