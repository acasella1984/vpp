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

package dhcpproxy

import (
	//"errors"

	"fmt"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/sase/common"
	"github.com/contiv/vpp/plugins/sase/config"
	"github.com/contiv/vpp/plugins/sase/renderer"
	"github.com/contiv/vpp/plugins/statscollector"
	"go.ligato.io/cn-infra/v2/logging"
	vpp_l3 "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/l3"
)

// Renderer implements rendering of dhcp proxy settings
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
	rndr.Log.Infof("Dhcp proxy service: Renderer Init")
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

	rndr.Log.Infof("Dhcp proxy service: Renderer AddServiceConfig %v %+v", sp, sp.Config)
	// We do not have a proto model for dhcp proxy service. This service internally derives the proxy
	// configuration from the POD and VPP Lan interface IP addresses.
	return rndr.CreateDhcpProxy(sp.ServiceInfo, sp.Config.(*common.PodInfo), reSync)
}

// UpdateServiceConfig :
func (rndr *Renderer) UpdateServiceConfig(old, new *config.SaseServiceConfig) error {

	// Check for service config type
	switch new.Config.(type) {
	case *common.PodInfo:
		return rndr.UpdateDhcpProxy(new.ServiceInfo, old.Config.(*common.PodInfo), new.Config.(*common.PodInfo))
	default:
	}
	return nil
}

// DeleteServiceConfig :
func (rndr *Renderer) DeleteServiceConfig(sp *config.SaseServiceConfig) error {
	// Check for service config type
	switch sp.Config.(type) {
	case *common.PodInfo:
		return rndr.DeleteDhcpProxy(sp.ServiceInfo, sp.Config.(*common.PodInfo))
	default:
	}
	return nil
}

/////////////////////////// Dhcp Proxy Related ////////////////

// CreateDhcpProxy adds new dhcp proxy server for a given source IP
func (rndr *Renderer) CreateDhcpProxy(serviceInfo *common.ServiceInfo, pod *common.PodInfo, reSync bool) error {

	rndr.Log.Infof("Dhcp proxy service: CreateDhcpProxy: ServiceInfo %v", serviceInfo, "PodInfo: %v", serviceInfo, pod)
	// Render dhcp proxy vpp proto buf
	ipAddrPool := rndr.GetVppLanInterfaceIPAddress(serviceInfo, "lan")

	dhcp_server := vpp_l3.DHCPProxy_DHCPServer{
		VrfId:     1,
		IpAddress: pod.IPAddress,
	}
	dhcp_proxy := vpp_l3.DHCPProxy{
		SourceIpAddress: ipAddrPool[0],
		RxVrfId:         0,
	}
	dhcp_proxy.Servers = append(dhcp_proxy.Servers, &dhcp_server)

	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_l3.DHCPProxyKey(dhcp_proxy.SourceIpAddress), &dhcp_proxy, config.Add)
	}

	// Commit is for local base vpp vswitch
	rndr.Log.Info(" DhcpProxy service: CreateDhcpProxy:  Post txn to local vpp agent",
		"Key: %s", "Value: %v", dhcp_proxy.SourceIpAddress, dhcp_proxy)
	if reSync == true {
		txn := rndr.ResyncTxnFactory()
		txn.Put(vpp_l3.DHCPProxyKey(dhcp_proxy.SourceIpAddress), &dhcp_proxy)
	} else {
		txn := rndr.UpdateTxnFactory(fmt.Sprintf("Dhcp Proxy Service %s", vpp_l3.DHCPProxyKey(dhcp_proxy.SourceIpAddress)))
		txn.Put(vpp_l3.DHCPProxyKey(dhcp_proxy.SourceIpAddress), &dhcp_proxy)
	}
	// TODO - should be committed to KVSDB. We run the dhcp proxy only on base vpp.
	//return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_l3.DHCPProxyKey(dhcp_proxy.SourceIpAddress), &dhcp_proxy, config.Add)
	return nil
}

// UpdateDhcpProxy updates existing dhcp proxy settings
func (rndr *Renderer) UpdateDhcpProxy(serviceInfo *common.ServiceInfo, old, new *common.PodInfo) error {

	rndr.Log.Infof("UpdateDhcpProxy: %v", new)
	return nil
}

// DeleteDhcpProxy deletes an existing dhcp proxy setting
func (rndr *Renderer) DeleteDhcpProxy(serviceInfo *common.ServiceInfo, pod *common.PodInfo) error {

	rndr.Log.Infof("Dhcp Proxy Service: DeleteDhcpProxy: ServiceInfo %v", serviceInfo, "PodInfo: %v", sp)

	// Render dhcp proxy vpp proto buf
	ipAddrPool := rndr.GetVppLanInterfaceIPAddress(serviceInfo, "lan")

	dhcp_server := vpp_l3.DHCPProxy_DHCPServer{
		VrfId:     1,
		IpAddress: pod.IPAddress,
	}
	dhcp_proxy := vpp_l3.DHCPProxy{
		SourceIpAddress: ipAddrPool[0],
		RxVrfId:         0,
	}
	dhcp_proxy.Servers = append(dhcp_proxy.Servers, &dhcp_server)

	// Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), vpp_l3.DHCPProxyKey(dhcp_proxy.SourceIpAddress), &dhcp_proxy, config.Delete)
	}

	// Commit is for local base vpp vswitch
	rndr.Log.Info(" DhcpProxy service: CreateDhcpProxy:  Post txn to local vpp agent",
		"Key: %s", "Value: %v", dhcp_proxy.SourceIpAddress, dhcp_proxy)

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("Dhcp Proxy Service %s", vpp_l3.DHCPProxyKey(dhcp_proxy.SourceIpAddress)))
	txn.Delete(vpp_l3.DHCPProxyKey(dhcp_proxy.SourceIpAddress))

	// TODO - should be committed to KVSDB. We run the dhcp proxy only on base vpp.
	//return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), vpp_l3.DHCPProxyKey(dhcp_proxy.SourceIpAddress), &dhcp_proxy, config.Delete)
	return nil
}

// GetVppLanInterfaceIPAddress: Return primary IP Address for a given Interface
func (rndr *Renderer) GetVppLanInterfaceIPAddress(serviceInfo *common.ServiceInfo, interfaceName string) []string {

	var ipAddrPool []string

	// Check Main VPP Interfaces
	if rndr.ContivConf.GetMainInterfaceName() == interfaceName {
		ipWithNetworks := rndr.ContivConf.GetMainInterfaceConfiguredIPs()
		rndr.Log.Info("GetVppLanInterfaceIPAddress: ipWithNetworks for MainVPPInterface: ", ipWithNetworks)
		for _, ipNet := range ipWithNetworks {
			// Add the Addresses associated with Main Interface to address pool
			ipAddrPool = append(ipAddrPool, ipNet.Address.String())
		}
		return ipAddrPool
	}

	// Check Other VPP Interfaces
	otherVppInterfaces := rndr.ContivConf.GetOtherVPPInterfaces()
	rndr.Log.Info("GetInterfaceNameWithIP: otherVppInterfaces: ", otherVppInterfaces)
	for _, oVppIntf := range otherVppInterfaces {
		if oVppIntf.InterfaceName == interfaceName {
			for _, ipNet := range oVppIntf.IPs {
				ipAddrPool = append(ipAddrPool, ipNet.Address.String())
			}
			return ipAddrPool
		}
	}
	return ipAddrPool
}
