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
	vpp_l3 "github.com/ligato/vpp-agent/api/models/vpp/l3"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/sase/config"
	"github.com/contiv/vpp/plugins/sase/renderer"
	"github.com/contiv/vpp/plugins/statscollector"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/pkg/models"
)

// Renderer implements rendering of Nat policies
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
	RemoteDB         nodesync.KVDBWithAtomic
}

// Init initializes the renderer.
func (rndr *Renderer) Init() error {
	if rndr.Config == nil {
		rndr.Config = config.DefaultRouteConfig()
	}
	return nil
}

// AddPolicy adds route related policies
func (rndr *Renderer) AddPolicy(sp *renderer.SaseServicePolicy) error {
	rndr.Log.Infof("Route Service: AddPolicy: ")
	// convert Sase Service Policy to native Route representation
	routeRule := convertSasePolicyToRouteRule(sp)
	rndr.Log.Infof("AddPolicy: routeRule: %v", routeRule)
	vppRoute := rndr.renderVppRoute(sp.Policy.Name, routeRule)
	rndr.Log.Infof("AddPolicy: vppRoute: %v", vppRoute)
	return renderer.Commit(rndr.RemoteDB, "eos-rtr", models.Key(vppRoute), vppRoute, renderer.ConfigAdd)
}

// UpdatePolicy updates exiting route related policies
func (rndr *Renderer) UpdatePolicy(old, new *renderer.SaseServicePolicy) error {
	return nil
}

// DeletePolicy deletes an existing route policy
func (rndr *Renderer) DeletePolicy(sp *renderer.SaseServicePolicy) error {
	return nil
}

// AfterInit starts asynchronous NAT session cleanup.
func (rndr *Renderer) AfterInit() error {
	return nil
}

// ConvertSasePolicyToFirewallRule: convert SaseServicePolicy to firewall policy
func convertSasePolicyToRouteRule(sp *renderer.SaseServicePolicy) *RouteRule {
	rule := &RouteRule{}
	return rule
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
	EgressIntf  *renderer.Interface
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
