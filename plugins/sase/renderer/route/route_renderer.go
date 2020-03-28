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

package routeservice

import (
	"fmt"

	vpp_l3 "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/l3"

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
		rndr.Config = config.DefaultRouteConfig()
	}
	return nil
}

// DeInit clean up service config
func (rndr *Renderer) DeInit() error {
	return nil
}

// AddServiceConfig :
func (rndr *Renderer) AddServiceConfig(sp *config.SaseServiceConfig) error {
	// Check for service config type
	switch sp.Config.(type) {
	case *sasemodel.SaseConfig:
		rndr.AddPolicy(sp.ServiceInfo, sp.Config.(*sasemodel.SaseConfig))
	case *RouteRule:
		rndr.AddServiceRoute(sp.ServiceInfo, sp.Config.(*RouteRule))
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
	case *RouteRule:
		rndr.DeleteServiceRoute(sp.ServiceInfo, sp.Config.(*RouteRule))
	default:
	}
	return nil
}

////////////////// Route Policies Renderer Routines ////////////////////

// AddPolicy adds route related policies
func (rndr *Renderer) AddPolicy(serviceInfo *common.ServiceInfo, sp *sasemodel.SaseConfig) error {
	rndr.Log.Infof("Route Service: AddPolicy: ")
	// convert Sase Service Policy to native Route representation
	routeRule := convertSasePolicyToRouteRule(sp)
	rndr.Log.Infof("AddPolicy: routeRule: %v", routeRule)
	vppRoute := rndr.renderVppRoute(sp.Name, routeRule)
	rndr.Log.Infof("AddPolicy: vppRoute: %v", vppRoute)
	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), models.Key(vppRoute), vppRoute, config.Add)
}

// UpdatePolicy updates exiting route related policies
func (rndr *Renderer) UpdatePolicy(serviceInfo *common.ServiceInfo, old, new *sasemodel.SaseConfig) error {
	return nil
}

// DeletePolicy deletes an existing route policy
func (rndr *Renderer) DeletePolicy(serviceInfo *common.ServiceInfo, sp *sasemodel.SaseConfig) error {
	return nil
}

// AfterInit starts asynchronous NAT session cleanup.
func (rndr *Renderer) AfterInit() error {
	return nil
}

// ConvertSasePolicyToFirewallRule: convert SaseServicePolicy to firewall policy
func convertSasePolicyToRouteRule(sp *sasemodel.SaseConfig) *RouteRule {
	rule := &RouteRule{}
	return rule
}

////////////////// Route Config Renderer Routines ////////////////////

// AddServiceRoute adds route entries
func (rndr *Renderer) AddServiceRoute(serviceInfo *common.ServiceInfo, sp *RouteRule) error {
	rndr.Log.Infof("Route Service: AddServiceRoute: ")

	vppRoute := &vpp_l3.Route{
		Type:       getVPPRouteType(sp.Type),
		VrfId:      sp.VrfID,
		DstNetwork: sp.DestNetwork,
		//NextHopAddr: sp.NextHop,
		//OutgoingInterface: sp.EgressIntf.Name,
		ViaVrfId: sp.EgressIntf.VrfID,
	}

	if sp.EgressIntf.Name != config.NotRequired {
		vppRoute.OutgoingInterface = sp.EgressIntf.Name
	}

	if sp.NextHop != config.NotRequired {
		vppRoute.NextHopAddr = sp.NextHop
	}

	// Mock Commit for Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), models.Key(vppRoute), vppRoute, config.Add)
	}

	// Commit is for local base vpp vswitch
	if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
		rndr.Log.Infof("Route Service: AddServiceRoute: Post txn to local vpp agent",
			"Key: ", models.Key(vppRoute), "Value: %v", vppRoute)
		txn := rndr.UpdateTxnFactory(fmt.Sprintf("Service Route %s", models.Key(vppRoute)))
		txn.Put(models.Key(vppRoute), vppRoute)
		return nil
	}

	rndr.Log.Infof("Route Service: AddServiceRoute: Post txn to remote CNF VPP Agent",
		"Key: ", models.Key(vppRoute), "Value: %v", vppRoute)
	// Commit is for the Remote VPP CNF
	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), models.Key(vppRoute), vppRoute, config.Add)
}

// DeleteServiceRoute deletes route entries
func (rndr *Renderer) DeleteServiceRoute(serviceInfo *common.ServiceInfo, sp *RouteRule) error {
	rndr.Log.Infof("Route Service: DeleteServiceRoute: ")

	vppRoute := &vpp_l3.Route{
		Type:        getVPPRouteType(sp.Type),
		VrfId:       sp.VrfID,
		DstNetwork:  sp.DestNetwork,
		//NextHopAddr: sp.NextHop,
		//OutgoingInterface: sp.EgressIntf.Name,
		ViaVrfId: sp.EgressIntf.VrfID,
	}

	if sp.EgressIntf.Name != config.NotRequired {
		vppRoute.OutgoingInterface = sp.EgressIntf.Name
	}

	if sp.NextHop != config.NotRequired {
		vppRoute.NextHopAddr = sp.NextHop
	}

	// Mock Commit for Test Purpose
	if rndr.MockTest {
		return renderer.MockCommit(serviceInfo.GetServicePodLabel(), models.Key(vppRoute), vppRoute, config.Add)
	}

	// Commit is for local base vpp vswitch
	if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
		rndr.Log.Infof("Route Service: DeleteServiceRoute: Post txn to local vpp agent",
			"Key: ", models.Key(vppRoute), "Value: %v", vppRoute)
		txn := rndr.UpdateTxnFactory(fmt.Sprintf("Service Route %s", models.Key(vppRoute)))
		txn.Delete(models.Key(vppRoute))
		return nil
	}

	// Commit is for the Remote VPP CNF
	rndr.Log.Infof("Route Service: DeleteServiceRoute: Post txn to remote CNF VPP Agent",
		"Key: ", models.Key(vppRoute), "Value: %v", vppRoute)
	return renderer.Commit(rndr.RemoteDB, serviceInfo.GetServicePodLabel(), models.Key(vppRoute), vppRoute, config.Delete)
}

// RouteType :
type RouteType int

const (
	// Local : No Nat configuration
	Local RouteType = iota
	// Drop :
	Drop
	// InterVrf :
	InterVrf
	// IntraVrf :
	IntraVrf
)

// RouteRule :
type RouteRule struct {
	Type        RouteType
	VrfID       uint32
	DestNetwork string
	NextHop     string
	EgressIntf  *config.Interface
}

func getVPPRouteType(r RouteType) vpp_l3.Route_RouteType {

	var rt vpp_l3.Route_RouteType

	switch r {
	case IntraVrf:
		rt = vpp_l3.Route_INTRA_VRF
	case InterVrf:
		rt = vpp_l3.Route_INTER_VRF
	case Drop:
		rt = vpp_l3.Route_DROP
	}
	return rt
}

// renderVppSNAT :: Renders VPP DNAT Config
func (rndr *Renderer) renderVppRoute(key string, routeRule *RouteRule) *vpp_l3.Route {
	routeCfg := &vpp_l3.Route{
		VrfId:             routeRule.VrfID,
		DstNetwork:        routeRule.DestNetwork,
		NextHopAddr:       routeRule.NextHop,
		OutgoingInterface: routeRule.EgressIntf.Name,
	}
	return routeCfg
}
