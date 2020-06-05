/*
 * // Copyright (c) 2019 Cisco and/or its affiliates.
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

package processor

import (
	"errors"
	"net"

	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/cn-infra/v2/servicelabel"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	sasemodel "github.com/contiv/vpp/plugins/crd/handler/saseconfig/model"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipam/ipalloc"
	"github.com/contiv/vpp/plugins/ipnet"
	"github.com/contiv/vpp/plugins/ksr/model/pod"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/contiv/vpp/plugins/sase/common"
	"github.com/contiv/vpp/plugins/sase/config"
	"github.com/contiv/vpp/plugins/sase/renderer"
	routeservice "github.com/contiv/vpp/plugins/sase/renderer/route"
)

// SaseServiceProcessor implements SaseProcessorAPI.
type SaseServiceProcessor struct {
	Deps
	renderers map[common.SaseServiceType]renderer.SaseServiceRendererAPI

	// Maintain local cache of all the sase service policies that are applied
	// Housekeeping stuff

	// podInfo DB
	podsList map[podmodel.ID]*common.PodInfo

	// Service Info
	services map[common.PodSaseServiceInfo]*common.ServiceInfo

	// Sase Service Policies
	servicePolicies map[string]*sasemodel.SaseConfig

	// Site Resource Groups
	siteResourceGroups map[string]*sasemodel.SiteResourceGroup

	// Security Associations
	securityAssociations map[string]*sasemodel.SecurityAssociation

	// IPSecVpnTunnels
	ipSecVpnTunnel map[string]*sasemodel.IPSecVpnTunnel

	// Network Firewall Profiles
	networkFirewallProfile map[string]*sasemodel.NetworkFirewallProfile
}

// Deps lists dependencies of SFC Processor.
type Deps struct {
	Log          logging.Logger
	ServiceLabel servicelabel.ReaderAPI
	ContivConf   contivconf.API
	NodeSync     nodesync.API
	PodManager   podmanager.API
	IPAM         ipam.API
	IPNet        ipnet.API
}

// Init initializes Sase processor.
func (sp *SaseServiceProcessor) Init() error {
	sp.Log.Debug("Sase Processor Init")
	sp.renderers = make(map[common.SaseServiceType]renderer.SaseServiceRendererAPI)
	sp.podsList = make(map[podmodel.ID]*common.PodInfo)
	sp.services = make(map[common.PodSaseServiceInfo]*common.ServiceInfo)
	sp.ipSecVpnTunnel = make(map[string]*sasemodel.IPSecVpnTunnel)
	return nil
}

// BaseVppPodServiceInit : Enabled services on the base vpp vswitch
// This can be later moved to Config Option via CRD (service enable/disable)
// VENKAT: TBD
func (sp *SaseServiceProcessor) BaseVppPodServiceInit() error {
	sp.Log.Debug("BaseVppServiceInit")

	// Init Base VPP vswitch Pod
	podID := podmodel.ID{Name: common.GetBaseServiceLabel(),
		Namespace: "default"}

	podInfo := &common.PodInfo{
		ID:    podID,
		Label: common.GetBaseServiceLabel(),
	}

	// Add Pod Info for the base vpp-vswitch
	sp.AddPodInfo(podID, podInfo)

	addService := common.GetBaseVppServices()
	sp.processServiceAddition(podID, addService)
	return nil
}

// reset (re)initializes all internal maps.
func (sp *SaseServiceProcessor) reset() {
}

// RegisterRenderer register sase service renderers
func (sp *SaseServiceProcessor) RegisterRenderer(name common.SaseServiceType,
	renderer renderer.SaseServiceRendererAPI) error {

	// register renderer
	sp.renderers[name] = renderer
	return nil
}

// GetRenderer returns sase service renderers identified by the name
func (sp *SaseServiceProcessor) GetRenderer(name common.SaseServiceType) (renderer.SaseServiceRendererAPI, error) {

	// register renderer
	rndr, ok := sp.renderers[name]
	if !ok {
		return nil, errors.New("GetRenderer: Renderer Not found")
	}
	sp.Log.Infof(" GetRenderer: rndr returned for Sase Service %d", name)
	return rndr, nil
}

// AfterInit does nothing for the SFC processor.
// VENKAT
func (sp *SaseServiceProcessor) AfterInit() error {
	return nil
}

// Update is called for:
//  - KubeStateChange for Sase-related config
func (sp *SaseServiceProcessor) Update(event controller.Event) error {
	sp.Log.Infof("Update: %v", event)
	if k8sChange, isK8sChange := event.(*controller.KubeStateChange); isK8sChange {
		switch k8sChange.Resource {
		case sasemodel.SasePolicyKey:
			if k8sChange.NewValue != nil {
				// Get the Sase Model Config Data.
				saseNewCfg := k8sChange.NewValue.(*sasemodel.SaseConfig)
				if k8sChange.PrevValue == nil {
					return sp.ProcessNewSaseServiceConfig(saseNewCfg, false)
				}
				sasePrevCfg := k8sChange.NewValue.(*sasemodel.SaseConfig)
				return sp.ProcessUpdateSaseServiceConfig(sasePrevCfg, saseNewCfg)
			}
			saseDelCfg := k8sChange.PrevValue.(*sasemodel.SaseConfig)
			return sp.ProcessDeletedSaseServiceConfig(saseDelCfg)
		case sasemodel.NetworkFirewallProfileKey:
			if k8sChange.NewValue != nil {
				// Get the network firewall profile
				networkFirewallProfileNewCfg := k8sChange.NewValue.(*sasemodel.NetworkFirewallProfile)
				if k8sChange.PrevValue == nil {
					return sp.ProcessNewNetworkFirewallProfileConfig(networkFirewallProfileNewCfg, false)
				}
				networkFirewallProfilePrevCfg := k8sChange.NewValue.(*sasemodel.NetworkFirewallProfile)
				return sp.ProcessUpdateNetworkFirewallProfileConfig(networkFirewallProfilePrevCfg, networkFirewallProfileNewCfg)
			}
			networkFirewallProfileDelCfg := k8sChange.PrevValue.(*sasemodel.NetworkFirewallProfile)
			return sp.ProcessDeletedNetworkFirewallProfileConfig(networkFirewallProfileDelCfg)

		case sasemodel.SecurityAssociationKey:
			if k8sChange.NewValue != nil {
				// Get the Security Association Config Data.
				saNewCfg := k8sChange.NewValue.(*sasemodel.SecurityAssociation)
				if k8sChange.PrevValue == nil {
					return sp.ProcessNewSecurityAssociationConfig(saNewCfg, false)
				}
				saPrevCfg := k8sChange.NewValue.(*sasemodel.SecurityAssociation)
				return sp.ProcessUpdateSecurityAssociationConfig(saPrevCfg, saNewCfg)
			}
			saDelCfg := k8sChange.PrevValue.(*sasemodel.SecurityAssociation)
			return sp.ProcessDeletedSecurityAssociationConfig(saDelCfg)
		case sasemodel.SiteResourceGroupKey:
			if k8sChange.NewValue != nil {
				// Get the Site Resource Config Data.
				srNewCfg := k8sChange.NewValue.(*sasemodel.SiteResourceGroup)
				if k8sChange.PrevValue == nil {
					return sp.ProcessNewSiteResourceConfig(srNewCfg, false)
				}
				srPrevCfg := k8sChange.NewValue.(*sasemodel.SiteResourceGroup)
				return sp.ProcessUpdateSiteResourceConfig(srPrevCfg, srNewCfg)
			}
			srDelCfg := k8sChange.PrevValue.(*sasemodel.SiteResourceGroup)
			return sp.ProcessDeletedSiteResourceConfig(srDelCfg)
		case sasemodel.IPSecVpnTunnelKey:
			if k8sChange.NewValue != nil {
				// Get the IpSec VPN Tunnel Config Data.
				ipsecNewCfg := k8sChange.NewValue.(*sasemodel.IPSecVpnTunnel)
				if k8sChange.PrevValue == nil {
					return sp.ProcessNewIPSecVpnTunnelConfig(ipsecNewCfg, false)
				}
				ipsecPrevCfg := k8sChange.NewValue.(*sasemodel.IPSecVpnTunnel)
				return sp.ProcessUpdateIPSecVpnTunnelConfig(ipsecPrevCfg, ipsecNewCfg)
			}
			ipsecDelCfg := k8sChange.PrevValue.(*sasemodel.IPSecVpnTunnel)
			return sp.ProcessDeletedIPSecVpnTunnelConfig(ipsecDelCfg)
		case sasemodel.ServiceRouteKey:
			if k8sChange.NewValue != nil {
				// Get the Service Route Config Data.
				serviceRouteNewCfg := k8sChange.NewValue.(*sasemodel.ServiceRoute)
				if k8sChange.PrevValue == nil {
					return sp.ProcessNewServiceRouteConfig(serviceRouteNewCfg, false)
				}
				serviceRoutePrevCfg := k8sChange.NewValue.(*sasemodel.ServiceRoute)
				return sp.ProcessUpdateServiceRouteConfig(serviceRoutePrevCfg, serviceRouteNewCfg)
			}
			serviceRouteDelCfg := k8sChange.PrevValue.(*sasemodel.ServiceRoute)
			return sp.ProcessDeletedServiceRouteConfig(serviceRouteDelCfg)
		case sasemodel.SaseServiceInterfaceKey:
			if k8sChange.NewValue != nil {
				// Get the Sase Service Interface
				serviceInterfaceNewCfg := k8sChange.NewValue.(*sasemodel.SaseServiceInterface)
				if k8sChange.PrevValue == nil {
					return sp.ProcessNewSaseServiceInterfaceConfig(serviceInterfaceNewCfg, false)
				}
				serviceInterfacePrevCfg := k8sChange.NewValue.(*sasemodel.SaseServiceInterface)
				return sp.ProcessUpdateSaseServiceInterfaceConfig(serviceInterfacePrevCfg, serviceInterfaceNewCfg)
			}
			serviceInterfaceDelCfg := k8sChange.PrevValue.(*sasemodel.SaseServiceInterface)
			return sp.ProcessDeletedSaseServiceInterfaceConfig(serviceInterfaceDelCfg)
		case podmodel.PodKeyword:
			if k8sChange.NewValue != nil {
				pod := k8sChange.NewValue.(*podmodel.Pod)
				if k8sChange.PrevValue == nil {
					return sp.ProcessNewPod(pod)
				}
				return sp.ProcessUpdatedPod(pod)
			}
			pod := k8sChange.PrevValue.(*podmodel.Pod)
			return sp.ProcessDeletedPod(pod)
		case ipalloc.Keyword:
			// Event received when IP addresses are assigned to Pod Custom Ifs because of
			// customnetwork config
			if k8sChange.NewValue != nil {
				alloc := k8sChange.NewValue.(*ipalloc.CustomIPAllocation)
				return sp.ProcessCustomIfIPAlloc(alloc)
			}
		default:
		}
	}

	return nil
}

// Resync processes a resync event.
// The cache content is fully replaced and all registered renderers
// receive a full snapshot of Sase Config at the present state to be (re)installed.
func (sp *SaseServiceProcessor) Resync(kubeStateData controller.KubeStateData) error {

	var reSync bool
	// reset internal state
	sp.reset()

	sp.Log.Infof("SaseServiceProcessor Resync: Start...")

	// Pod and IP Alloc are relevant for VPP based CNFs with customIfs and customNetworks
	// Rebuild Pod DB Information
	for _, podsProto := range kubeStateData[podmodel.PodKeyword] {
		pod := podsProto.(*podmodel.Pod)
		sp.Log.Infof("Resync Pods Information: %v", pod)
		sp.ProcessNewPod(pod)
	}

	// Rebuild Pod DB Information
	for _, ipAllocProto := range kubeStateData[ipalloc.Keyword] {
		cIP := ipAllocProto.(*ipalloc.CustomIPAllocation)
		sp.Log.Infof("Resync CustomIP Allocation: %v", cIP)
		sp.ProcessCustomIfIPAlloc(cIP)
	}

	// Resync Event
	reSync = true

	// rebuild Security Associations renderer config
	for _, securityAssociationProto := range kubeStateData[sasemodel.SecurityAssociationKey] {
		sA := securityAssociationProto.(*sasemodel.SecurityAssociation)
		sp.Log.Infof("Resync SecurityAssociations: %v", sA)
		sp.ProcessNewSecurityAssociationConfig(sA, reSync)

	}

	// // rebuild IPSec VPN Tunnel rendered configuration
	for _, ipSecTunnelProto := range kubeStateData[sasemodel.IPSecVpnTunnelKey] {
		ipS := ipSecTunnelProto.(*sasemodel.IPSecVpnTunnel)
		sp.Log.Infof("Resync IPSecTunnels: %v", ipS)
		sp.ProcessNewIPSecVpnTunnelConfig(ipS, reSync)
	}

	// rebuild ServiceRoute renderer configuration
	for _, serviceRouteProto := range kubeStateData[sasemodel.ServiceRouteKey] {
		sR := serviceRouteProto.(*sasemodel.ServiceRoute)
		sp.Log.Infof("Resync Service Routes: %v", sR)
		sp.ProcessNewServiceRouteConfig(sR, reSync)

	}

	// rebuild Sase Policy renderer configurations
	for _, sasePolicyProto := range kubeStateData[sasemodel.SasePolicyKey] {
		sP := sasePolicyProto.(*sasemodel.SaseConfig)
		sp.Log.Infof("Resync Sase Policies: %v", sP)
		sp.ProcessNewSaseServiceConfig(sP, reSync)
	}

	sp.Log.Infof("SaseServiceProcessor Resync: Done...")
	return nil
}

// Close does nothing for the Sase processor.
func (sp *SaseServiceProcessor) Close() error {
	return nil
}

//////////////////////////////// Sase Policies Processor Routines ////////////////////////

// ProcessNewSaseServiceConfig :
func (sp *SaseServiceProcessor) ProcessNewSaseServiceConfig(cfg *sasemodel.SaseConfig, reSync bool) error {
	sp.Log.Infof("processNewSaseServiceConfig: %v", cfg)

	s, _ := common.ParseSaseServiceName(cfg.ServiceInstanceName)
	serviceInfo, ok := sp.services[s]
	if !ok {
		return errors.New("processNewSaseServiceConfig: Service Not Enabled")
	}
	rndr, err := sp.GetRenderer(serviceInfo.GetServiceType())
	if err != nil {
		return err
	}

	// Fill in the relevant information
	p := &config.SaseServiceConfig{
		ServiceInfo: serviceInfo,
		Config:      cfg,
	}
	err = rndr.AddServiceConfig(p, reSync)
	return err
}

// ProcessUpdateSaseServiceConfig :
func (sp *SaseServiceProcessor) ProcessUpdateSaseServiceConfig(old, new *sasemodel.SaseConfig) error {
	sp.Log.Infof("processUpdateSaseServiceConfig: old: %v new: %v", old, new)
	s, _ := common.ParseSaseServiceName(new.ServiceInstanceName)
	serviceInfo, ok := sp.services[s]
	if !ok {
		return errors.New("processUpdateSaseServiceConfig: Service Not Enabled")
	}
	rndr, err := sp.GetRenderer(serviceInfo.GetServiceType())
	if err != nil {
		return err
	}

	// Fill in the relevant information
	oldP := &config.SaseServiceConfig{
		ServiceInfo: serviceInfo,
		Config:      old,
	}
	newP := &config.SaseServiceConfig{
		ServiceInfo: serviceInfo,
		Config:      new,
	}
	err = rndr.UpdateServiceConfig(oldP, newP)
	return err
}

// ProcessDeletedSaseServiceConfig :
func (sp *SaseServiceProcessor) ProcessDeletedSaseServiceConfig(cfg *sasemodel.SaseConfig) error {
	sp.Log.Infof("processDeletedSaseServiceConfig: %v", cfg)
	s, _ := common.ParseSaseServiceName(cfg.ServiceInstanceName)
	serviceInfo, ok := sp.services[s]
	if !ok {
		return errors.New("processDeletedSaseServiceConfig: Service Not Enabled")
	}
	rndr, err := sp.GetRenderer(serviceInfo.GetServiceType())
	if err != nil {
		return err
	}

	// Fill in the relevant information
	p := &config.SaseServiceConfig{
		ServiceInfo: serviceInfo,
		Config:      cfg,
	}
	err = rndr.DeleteServiceConfig(p)
	return err
}

//////////////////////////////// Network Firewall Profile Routines ////////////////////////

// ProcessNewNetworkFirewallProfileConfig :
func (sp *SaseServiceProcessor) ProcessNewNetworkFirewallProfileConfig(cfg *sasemodel.NetworkFirewallProfile, reSync bool) error {
	sp.Log.Infof("ProcessNewNetworkFirewallProfileConfig: %v", cfg)

	s, _ := common.ParseSaseServiceName(cfg.ServiceInstanceName)
	serviceInfo, ok := sp.services[s]
	if !ok {
		return errors.New("ProcessNewNetworkFirewallProfileConfig: Service Not Enabled")
	}
	rndr, err := sp.GetRenderer(serviceInfo.GetServiceType())
	if err != nil {
		return err
	}

	// Fill in the relevant information
	p := &config.SaseServiceConfig{
		ServiceInfo: serviceInfo,
		Config:      cfg,
	}
	err = rndr.AddServiceConfig(p, reSync)
	return err
}

// ProcessUpdateNetworkFirewallProfileConfig :
func (sp *SaseServiceProcessor) ProcessUpdateNetworkFirewallProfileConfig(old, new *sasemodel.NetworkFirewallProfile) error {
	sp.Log.Infof("ProcessUpdateNetworkFirewallProfileConfig: old: %v new: %v", old, new)
	s, _ := common.ParseSaseServiceName(new.ServiceInstanceName)
	serviceInfo, ok := sp.services[s]
	if !ok {
		return errors.New("ProcessUpdateNetworkFirewallProfileConfig: Service Not Enabled")
	}
	rndr, err := sp.GetRenderer(serviceInfo.GetServiceType())
	if err != nil {
		return err
	}

	// Fill in the relevant information
	oldP := &config.SaseServiceConfig{
		ServiceInfo: serviceInfo,
		Config:      old,
	}
	newP := &config.SaseServiceConfig{
		ServiceInfo: serviceInfo,
		Config:      new,
	}
	err = rndr.UpdateServiceConfig(oldP, newP)
	return err
}

// ProcessDeletedNetworkFirewallProfileConfig :
func (sp *SaseServiceProcessor) ProcessDeletedNetworkFirewallProfileConfig(cfg *sasemodel.NetworkFirewallProfile) error {
	sp.Log.Infof("ProcessDeletedNetworkFirewallProfileConfig: %v", cfg)
	s, _ := common.ParseSaseServiceName(cfg.ServiceInstanceName)
	serviceInfo, ok := sp.services[s]
	if !ok {
		return errors.New("ProcessDeletedNetworkFirewallProfileConfig: Service Not Enabled")
	}
	rndr, err := sp.GetRenderer(serviceInfo.GetServiceType())
	if err != nil {
		return err
	}

	// Fill in the relevant information
	p := &config.SaseServiceConfig{
		ServiceInfo: serviceInfo,
		Config:      cfg,
	}
	err = rndr.DeleteServiceConfig(p)
	return err
}


//////////////////////////////// Site Resource Group Processor Routines ////////////////////////

// ProcessNewSiteResourceConfig :
// Site Resource Group consists of local and public networks and any other relevant resource information
// within a site.
func (sp *SaseServiceProcessor) ProcessNewSiteResourceConfig(cfg *sasemodel.SiteResourceGroup, reSync bool) error {
	sp.Log.Infof("processNewSiteResourceConfig: %v", cfg)
	return nil
}

// ProcessUpdateSiteResourceConfig :
func (sp *SaseServiceProcessor) ProcessUpdateSiteResourceConfig(old, new *sasemodel.SiteResourceGroup) error {
	sp.Log.Infof("processUpdateSiteResourceConfig: old: %v new: %v", old, new)
	return nil
}

// ProcessDeletedSiteResourceConfig :
func (sp *SaseServiceProcessor) ProcessDeletedSiteResourceConfig(cfg *sasemodel.SiteResourceGroup) error {
	sp.Log.Infof("processDeletedSiteResourceConfig: %v", cfg)
	return nil
}

//////////////////////////////// Security Association Processor Routines ////////////////////////

// ProcessNewSecurityAssociationConfig :
func (sp *SaseServiceProcessor) ProcessNewSecurityAssociationConfig(cfg *sasemodel.SecurityAssociation, reSync bool) error {
	sp.Log.Infof("processNewSecurityAssociationConfig: %v", cfg)
	s, _ := common.ParseSaseServiceName(cfg.ServiceInstanceName)
	serviceInfo, ok := sp.services[s]
	if !ok {
		return errors.New("processNewSecurityAssociationConfig: Service Not Enabled")
	}
	rndr, err := sp.GetRenderer(serviceInfo.GetServiceType())
	if err != nil {
		return err
	}

	// Fill in the relevant information
	p := &config.SaseServiceConfig{
		ServiceInfo: serviceInfo,
		Config:      cfg,
	}
	err = rndr.AddServiceConfig(p, reSync)
	return err
}

// ProcessUpdateSecurityAssociationConfig :
func (sp *SaseServiceProcessor) ProcessUpdateSecurityAssociationConfig(old, new *sasemodel.SecurityAssociation) error {
	sp.Log.Infof("processUpdateSecurityAssociationConfig: old: %v new: %v", old, new)
	return nil
}

// ProcessDeletedSecurityAssociationConfig :
func (sp *SaseServiceProcessor) ProcessDeletedSecurityAssociationConfig(cfg *sasemodel.SecurityAssociation) error {

	sp.Log.Infof("processDeletedSecurityAssociationConfig: %v", cfg)
	s, _ := common.ParseSaseServiceName(cfg.ServiceInstanceName)
	serviceInfo, ok := sp.services[s]
	if !ok {
		return errors.New("processDeletedSecurityAssociationConfig: Service Not Enabled")
	}
	rndr, err := sp.GetRenderer(serviceInfo.GetServiceType())
	if err != nil {
		return err
	}

	// Fill in the relevant information
	p := &config.SaseServiceConfig{
		ServiceInfo: serviceInfo,
		Config:      cfg,
	}
	err = rndr.DeleteServiceConfig(p)
	return err
}

//////////////////////////////// IPSec Vpn Tunnel Processor Routines ////////////////////////

// ProcessNewIPSecVpnTunnelConfig :
func (sp *SaseServiceProcessor) ProcessNewIPSecVpnTunnelConfig(cfg *sasemodel.IPSecVpnTunnel, reSync bool) error {
	sp.Log.Infof("processNewIPSecVpnTunnelConfig: %v", cfg)
	s, _ := common.ParseSaseServiceName(cfg.ServiceInstanceName)
	serviceInfo, ok := sp.services[s]
	if !ok {
		return errors.New("processNewIPSecVpnTunnelConfig: Service Not Enabled")
	}
	rndr, err := sp.GetRenderer(serviceInfo.GetServiceType())
	if err != nil {
		return err
	}

	// Fill in the relevant information
	p := &config.SaseServiceConfig{
		ServiceInfo: serviceInfo,
		Config:      cfg,
	}
	err = rndr.AddServiceConfig(p, reSync)

	// Cache the tunnel information which could be referenced in other Sase configurations
	// eg. Route Config
	sp.ipSecVpnTunnel[cfg.TunnelName] = cfg
	return err
}

// ProcessUpdateIPSecVpnTunnelConfig :
func (sp *SaseServiceProcessor) ProcessUpdateIPSecVpnTunnelConfig(old, new *sasemodel.IPSecVpnTunnel) error {
	sp.Log.Infof("ProcessUpdateIPSecVpnTunnelConfig: old: %v new: %v", old, new)
	return nil
}

// ProcessDeletedIPSecVpnTunnelConfig :
func (sp *SaseServiceProcessor) ProcessDeletedIPSecVpnTunnelConfig(cfg *sasemodel.IPSecVpnTunnel) error {
	sp.Log.Infof("ProcessDeletedIPSecVpnTunnelConfig: %v", cfg)
	s, _ := common.ParseSaseServiceName(cfg.ServiceInstanceName)
	serviceInfo, ok := sp.services[s]
	if !ok {
		return errors.New("processDeletedIPSecVpnTunnelConfig: Service Not Enabled")
	}
	rndr, err := sp.GetRenderer(serviceInfo.GetServiceType())
	if err != nil {
		return err
	}

	// Fill in the relevant information
	p := &config.SaseServiceConfig{
		ServiceInfo: serviceInfo,
		Config:      cfg,
	}
	err = rndr.DeleteServiceConfig(p)
	return err
}

//////////////////////////////// Service Route Processor Routines ////////////////////////

// ProcessNewServiceRouteConfig :
func (sp *SaseServiceProcessor) ProcessNewServiceRouteConfig(cfg *sasemodel.ServiceRoute, reSync bool) error {
	sp.Log.Infof("ProcessNewServiceRouteConfig: %v", cfg)

	var routeVrf uint32
	var egrIntf string
	var egrVrfID uint32
	var gatewayIP string
	var routeType routeservice.RouteType

	s, _ := common.ParseSaseServiceName(cfg.ServiceInstanceName)
	serviceInfo, ok := sp.services[s]
	if !ok {
		return errors.New("ProcessNewServiceRouteConfig: Service Not Enabled")
	}

	// Routing is not tied to any service.
	rndr, err := sp.GetRenderer(serviceInfo.GetServiceType())
	if err != nil {
		return err
	}

	// Get Gateway service info
	g, err := common.ParseSaseServiceName(cfg.GatewayServiceId)
	gatewayService, ok := sp.services[g]
	if !ok {
		return errors.New("ProcessNewServiceRouteConfig: Service Not Enabled")
	}

	// Get VRF information where route needs to be installed
	if common.IsGlobalVrf(cfg.RouteNetworkScope) == true {
		routeVrf = sp.ContivConf.GetRoutingConfig().MainVRFID
	} else {
		routeVrf, _ = sp.IPNet.GetOrAllocateVrfID(cfg.RouteNetworkScope)
	}

	sp.Log.Info("ProcessNewServiceRouteConfig: vrf for the route installation", routeVrf)

	// Case 1: Route to be added in base vswitch destined towards a remote VPP CNF
	// Case 2: Route being added within base vswitch destined to external networks
	// Case 3: What about route to DDI apps - TBD
	if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
		if gatewayService.GetServicePodLabel() != common.GetBaseServiceLabel() {
			sp.Log.Info("ProcessNewServiceRouteConfig: Route added in base vpp towards VPP CNF", serviceInfo, gatewayService)
			// Case 1:
			// Get Egress Interface information to reach Remote Service
			// Get Gateway Interface Info
			intfInfo, err := gatewayService.Pod.GetPodInterfaceInfoInCustomNet(cfg.GatewayNetworkScope)
			if err != nil {
				return err
			}

			// gateway IP
			gatewayIP = intfInfo.IPAddress
			// Get Egress Interface Name
			egrIntf, _, _ = sp.IPNet.GetPodCustomIfNames(gatewayService.Pod.ID.Namespace,
				gatewayService.Pod.ID.Name, intfInfo.Name)
			egrVrfID = intfInfo.VrfID
		} else {
			// Case 2 or Case 3 or Case4
			// Expected to have a valid Next Hop IP Address
			// Valid Gateway IP Address is provided, then we don't need to derive egress Interface

			// Check if egress interface is a tunnel Interface
			if _, ok := sp.ipSecVpnTunnel[cfg.EgressInterface]; ok {
				egrIntf = cfg.EgressInterface
				gatewayIP = config.NotRequired
			} else {

				ip := net.ParseIP(cfg.GatewayAddress)
				if ip.To4() == nil {
					sp.Log.Info("ProcessNewServiceRouteConfig: Invalid IP Address", cfg.GatewayAddress)
					return nil
				}
				gatewayIP = cfg.GatewayAddress
				// Egress Interface?? Is it required?? To Check - VENKAT
				egrIntf = config.NotRequired
			}
			// Get VRF information where route needs to be installed
			if common.IsGlobalVrf(cfg.GatewayNetworkScope) == true {
				egrVrfID = sp.ContivConf.GetRoutingConfig().MainVRFID
			} else {
				egrVrfID, _ = sp.IPNet.GetOrAllocateVrfID(cfg.GatewayNetworkScope)
			}
		}
	} else {

		// Valid Gateway IP Address is provided, then we don't need to derive egress Interface
		// Check if egress interface is a tunnel Interface
		if _, ok := sp.ipSecVpnTunnel[cfg.EgressInterface]; ok {
			egrIntf = cfg.EgressInterface
			gatewayIP = config.NotRequired
		} else {
			ip := net.ParseIP(cfg.GatewayAddress)
			if ip.To4() == nil {
				sp.Log.Info("ProcessNewServiceRouteConfig: Invalid IP Address", cfg.GatewayAddress)
				// Case 4: Route to be added in Remote VPP CNF destined towards base vswitch
				// Assumption here is there is only one interface in the given networkScope that leads towards
				// base VPP
				intfInfo, err := serviceInfo.Pod.GetPodInterfaceInfoInCustomNet(cfg.GatewayNetworkScope)
				if err != nil {
					return err
				}
				// gateway IP
				gatewayIP = sp.IPAM.PodGatewayIP(cfg.GatewayNetworkScope).String()
				// Get Egress Interface Name
				egrIntf = intfInfo.Name
			} else {
				gatewayIP = cfg.GatewayAddress
				egrIntf = config.NotRequired
			}
			egrVrfID = sp.ContivConf.GetRoutingConfig().MainVRFID
		}
	}

	// Route Type. Route Installation Vrf and egress interface Vrf if different, then InterVrf
	routeType = routeservice.IntraVrf
	if routeVrf != egrVrfID {
		routeType = routeservice.InterVrf
	}

	sp.Log.Info("ProcessNewServiceRouteConfig: gatewayIp: ", gatewayIP, "egrIntf: ", egrIntf, "egrVrfID: ", egrVrfID)

	routeInfo := &routeservice.RouteRule{
		Type:        routeType,
		VrfID:       routeVrf,
		DestNetwork: cfg.DestinationNetwork,
		NextHop:     gatewayIP,
		EgressIntf: &config.Interface{
			Name:  egrIntf,
			VrfID: egrVrfID},
	}

	sp.Log.Infof("ProcessNewServiceRouteConfig: RouteInfo: %v", routeInfo)

	// Fill in the relevant information
	p := &config.SaseServiceConfig{
		ServiceInfo: serviceInfo,
		Config:      routeInfo,
	}
	err = rndr.AddServiceConfig(p, reSync)
	return err
}

// ProcessUpdateServiceRouteConfig :
func (sp *SaseServiceProcessor) ProcessUpdateServiceRouteConfig(old, new *sasemodel.ServiceRoute) error {
	sp.Log.Infof("ProcessUpdateServiceRouteConfig: old: %v new: %v", old, new)
	return nil
}

// ProcessDeletedServiceRouteConfig :
// VENKAT:: Can be merge Add/Del/Update as most of the code can be re-used. TBD
func (sp *SaseServiceProcessor) ProcessDeletedServiceRouteConfig(cfg *sasemodel.ServiceRoute) error {
	sp.Log.Infof("ProcessDeletedServiceRouteConfig: %v", cfg)
	var routeVrf uint32
	var egrIntf string
	var egrVrfID uint32
	var gatewayIP string
	var routeType routeservice.RouteType

	s, _ := common.ParseSaseServiceName(cfg.ServiceInstanceName)
	serviceInfo, ok := sp.services[s]
	if !ok {
		return errors.New("ProcessDeletedServiceRouteConfig: Service Not Enabled")
	}

	rndr, err := sp.GetRenderer(serviceInfo.GetServiceType())
	if err != nil {
		return err
	}

	// Get VRF information where route needs to be installed
	if common.IsGlobalVrf(cfg.RouteNetworkScope) == true {
		routeVrf = sp.ContivConf.GetRoutingConfig().MainVRFID
	} else {
		routeVrf, _ = sp.IPNet.GetOrAllocateVrfID(cfg.RouteNetworkScope)
	}

	// Get Gateway service info
	// Move it inside base vpp case
	g, err := common.ParseSaseServiceName(cfg.GatewayServiceId)
	gatewayService, ok := sp.services[g]
	if !ok {
		return errors.New("ProcessDeletedServiceRouteConfig: Service Not Enabled")
	}

	sp.Log.Info("ProcessDeletedServiceRouteConfig: vrf for the route installation", routeVrf)

	// Case 1: Route to be added in base vswitch destined towards a remote VPP CNF
	// Case 2: Route being added within base vswitch destined to external networks
	// Case 3: What about route to DDI apps - TBD
	// Case 4: Routes in Custom VRF in base vpp vswitch
	if serviceInfo.GetServicePodLabel() == common.GetBaseServiceLabel() {
		if gatewayService.GetServicePodLabel() != common.GetBaseServiceLabel() {
			sp.Log.Info("ProcessDeletedServiceRouteConfig: Route added in base vpp towards VPP CNF", serviceInfo, gatewayService)
			// Case 1:
			// Get Egress Interface information to reach Remote Service
			// Get Gateway Interface Info
			intfInfo, err := gatewayService.Pod.GetPodInterfaceInfoInCustomNet(cfg.GatewayNetworkScope)
			if err != nil {
				return err
			}

			// gateway IP
			gatewayIP = intfInfo.IPAddress
			// Get Egress Interface Name
			egrIntf, _, _ = sp.IPNet.GetPodCustomIfNames(gatewayService.Pod.ID.Namespace,
				gatewayService.Pod.ID.Name, intfInfo.Name)
			egrVrfID = intfInfo.VrfID
		} else {
			// Case 2 or Case 3 or Case4
			// Expected to have a valid Next Hop IP Address
			// Valid Gateway IP Address is provided, then we don't need to derive egress Interface
			// Check if egress interface is a tunnel Interface
			if _, ok := sp.ipSecVpnTunnel[cfg.EgressInterface]; ok {
				egrIntf = cfg.EgressInterface
				gatewayIP = config.NotRequired
			} else {
				ip := net.ParseIP(cfg.GatewayAddress)
				if ip.To4() == nil {
					sp.Log.Info("ProcessDeletedServiceRouteConfig: Invalid IP Address", cfg.GatewayAddress)
					return nil
				}
				gatewayIP = cfg.GatewayAddress
				// Egress Interface?? Is it required?? To Check - VENKAT
				egrIntf = config.NotRequired
			}
			// Get VRF information where route needs to be installed
			if common.IsGlobalVrf(cfg.GatewayNetworkScope) == true {
				egrVrfID = sp.ContivConf.GetRoutingConfig().MainVRFID
			} else {
				egrVrfID, _ = sp.IPNet.GetOrAllocateVrfID(cfg.GatewayNetworkScope)
			}
		}

	} else {
		// Case 4: Route to be added in Remote VPP CNF destined towards base vswitch
		// Valid Gateway IP Address is provided, then we don't need to derive egress Interface
		if _, ok := sp.ipSecVpnTunnel[cfg.EgressInterface]; ok {
			egrIntf = cfg.EgressInterface
			gatewayIP = config.NotRequired
		} else {
			ip := net.ParseIP(cfg.GatewayAddress)
			if ip.To4() == nil {
				sp.Log.Info("ProcessDeletedServiceRouteConfig: Invalid IP Address", cfg.GatewayAddress)
				// Case 4: Route to be added in Remote VPP CNF destined towards base vswitch
				// Assumption here is there is only one interface in the given networkScope that leads towards
				// base VPP
				intfInfo, err := serviceInfo.Pod.GetPodInterfaceInfoInCustomNet(cfg.GatewayNetworkScope)
				if err != nil {
					return err
				}
				// gateway IP
				gatewayIP = sp.IPAM.PodGatewayIP(cfg.GatewayNetworkScope).String()
				// Get Egress Interface Name
				egrIntf = intfInfo.Name
			} else {
				gatewayIP = cfg.GatewayAddress
				egrIntf = config.NotRequired
			}
		}
	}

	// Route Type. Route Installation Vrf and egress interface Vrf if different, then InterVrf
	routeType = routeservice.IntraVrf
	if routeVrf != egrVrfID {
		routeType = routeservice.InterVrf
	}

	sp.Log.Info("ProcessDeletedServiceRouteConfig: gatewayIp: ", gatewayIP, "egrIntf: ", egrIntf, "egrVrfID: ", egrVrfID)

	routeInfo := &routeservice.RouteRule{
		Type:        routeType,
		VrfID:       routeVrf,
		DestNetwork: cfg.DestinationNetwork,
		NextHop:     gatewayIP,
		EgressIntf: &config.Interface{
			Name:  egrIntf,
			VrfID: egrVrfID},
	}

	sp.Log.Infof("ProcessDeletedServiceRouteConfig: RouteInfo: %v", routeInfo)

	// Fill in the relevant information
	p := &config.SaseServiceConfig{
		ServiceInfo: serviceInfo,
		Config:      routeInfo,
	}
	err = rndr.DeleteServiceConfig(p)
	return err
}

//////////////////////////////// Service Route Processor Routines ////////////////////////

// ProcessNewSaseServiceInterfaceConfig :
func (sp *SaseServiceProcessor) ProcessNewSaseServiceInterfaceConfig(cfg *sasemodel.SaseServiceInterface, reSync bool) error {

	sp.Log.Infof("ProcessNewSaseServiceInterfaceConfig: cfg %v", cfg)
	return nil
}

// ProcessUpdateSaseServiceInterfaceConfig :
func (sp *SaseServiceProcessor) ProcessUpdateSaseServiceInterfaceConfig(old, new *sasemodel.SaseServiceInterface) error {

	sp.Log.Infof("ProcessUpdateSaseServiceInterfaceConfig: old: %v new: %v", old, new)
	return nil
}

// ProcessDeletedSaseServiceInterfaceConfig :
func (sp *SaseServiceProcessor) ProcessDeletedSaseServiceInterfaceConfig(cfg *sasemodel.SaseServiceInterface) error {

	sp.Log.Infof("ProcessDeletedSaseServiceInterfaceConfig: cfg %v", cfg)
	return nil
}


/////////////////////////// Pod Events ////////////////////////////////////////////

// GetPodInfo : Get PodInfo for given pidId
func (sp *SaseServiceProcessor) GetPodInfo(podID pod.ID) (*common.PodInfo, error) {

	info, ok := sp.podsList[podID]
	if !ok {
		return nil, errors.New("GetPodInfo: Pod Info Not Found")
	}

	return info, nil

}

// AddPodInfo : Add PodInfo to podlist for given podID
func (sp *SaseServiceProcessor) AddPodInfo(podID pod.ID, podInfo *common.PodInfo) error {

	_, ok := sp.podsList[podID]
	if !ok {
		// PodInfo Not present in the podlist
		// Add
		sp.podsList[podID] = podInfo
		sp.Log.Debugf("AddPodInfo: Added PodInfo to the podList %v", podInfo)
	}

	return nil
}

// DeletePodInfo : Delete PodInfo from podlist for given podID
func (sp *SaseServiceProcessor) DeletePodInfo(podID pod.ID) error {

	info, ok := sp.podsList[podID]
	if !ok {
		sp.Log.Errorf("DeletePodInfo: PodInfo Not Found PodId ", podID)
		// VENKAT: Return Error here. TBD
	}

	sp.Log.Debugf("DeletePodInfo: Deleted PodInfo from the podList %v", info)
	// Delete PodInfo from the PodList
	delete(sp.podsList, podID)
	return nil
}

// ProcessNewPod handles the event of adding of a new pod.
func (sp *SaseServiceProcessor) ProcessNewPod(pod *podmodel.Pod) error {
	return sp.ProcessUpdatedPod(pod)
}

// ProcessUpdatedPod handles the event of updating runtime state of a pod.
// Service Add/Delete intent can be sent via Pod annotations and actions
// corresponding to Service Addition, Deletion to be taken.
func (sp *SaseServiceProcessor) ProcessUpdatedPod(pod *podmodel.Pod) error {
	// ignore pods without IP (not yet scheduled)
	if pod.IpAddress == "" {
		return nil
	}

	sp.Log.Infof("New / Updated pod: %v", pod)

	// Get podID
	podID := podmodel.GetID(pod)

	// Handle CNF Pod Microservice label annotations
	_, ok := sp.podsList[podID]
	if !ok {
		// New Pod Event
		// Housekeep Pod Information
		label := common.GetContivMicroserviceLabel(pod.Annotations)
		if label == common.NotAvailable {
			return nil
		}
		podInfo := &common.PodInfo{
			ID:    podID,
			Label: label,
		}
		// Add PodInfo to the podlist
		sp.AddPodInfo(podID, podInfo)
	}

	// Handle CNF Pod interface updates
	if common.HasContivCustomIfs(pod.Annotations) == true {
		var podInterfaceList []common.PodInterfaceInfo
		podCustomIfs := common.GetContivCustomIfs(pod.Annotations)
		for _, customIf := range podCustomIfs {
			customIfInfo, _ := common.ParseCustomIfInfo(customIf)
			sp.Log.Infof("New / Updated pod: customIfInfo %v", customIfInfo)
			podInterfaceList = append(podInterfaceList, customIfInfo)
		}

		sp.podsList[podID].UpdateInterfaceList(podInterfaceList)

	}

	// Handle Service Updates
	if common.HasSaseServicesAnnotation(pod.Annotations) == true {
		var saseServiceList []common.PodSaseServiceInfo
		saseServices := common.GetSaseServices(pod.Annotations)
		for _, saseService := range saseServices {
			saseServiceInfo, _ := common.ParseSaseServiceName(saseService)
			sp.Log.Infof("New / Updated pod: SaseServiceInfo %v", saseServiceInfo)
			saseServiceList = append(saseServiceList, saseServiceInfo)
		}

		// Check for updates in the sase services deployed on the pod.
		// New services added or existing services deleted
		newServices, deletedServices := getPodUpdateServiceList(saseServiceList, sp.podsList[podID].ServiceList)
		sp.Log.Info("New / Updated pod: newServices: ", newServices, "deletedServices: ", deletedServices)
		sp.processServiceAddition(podID, newServices)
		sp.processServiceDeletion(podID, deletedServices)
	}

	sp.Log.Infof("processUpdatedPod: PodList %v", sp.podsList[podID])
	sp.Log.Infof(" processUpdatedPod: Service List %v", sp.services)

	return nil
}

// ProcessDeletedPod handles the event of deletion of a pod.
func (sp *SaseServiceProcessor) ProcessDeletedPod(pod *podmodel.Pod) error {

	sp.Log.Debugf("Delete pod: %v", pod)
	podID := podmodel.GetID(pod)

	// Cleanup Service related information on Pod Delete trigger.
	// Service existence no longer relevant when Pod is deleted
	podInfo, err := sp.GetPodInfo(podID)
	if err != nil {
		sp.Log.Errorf("processDeletedPod: Pod Not Found: ", podID)
		// VENKAT:: To return error here. TBD
		return nil
	}
	sp.Log.Info("processDeletedPod: deletedServices: ", podInfo.ServiceList)
	err = sp.processServiceDeletion(podID, podInfo.ServiceList)
	if err != nil {
		sp.Log.Errorf("processServiceDeletion: error returned", err)
	}

	// Delete PodInfo from the Podlist
	sp.DeletePodInfo(podID)
	return nil
}

// processUpdatedPodCustomIfs handles the event of updating pod custom interfaces.
func (sp *SaseServiceProcessor) processUpdatedPodCustomIfs(pod *ipnet.PodCustomIfUpdate) error {

	podData := sp.PodManager.GetPods()[pod.PodID]
	if podData == nil {
		return nil
	}
	sp.Log.Debugf("Update pod custom ifs: %v", podData)
	return nil
}

// podMatchesSelector returns true if the pod matches provided label selector, false otherwise.
func (sp *SaseServiceProcessor) podMatchesSelector(pod *podmanager.Pod, podSelector map[string]string) bool {
	if len(pod.Labels) == 0 {
		return false
	}
	for selKey, selVal := range podSelector {
		match := false
		for podLabelKey, podLabelVal := range pod.Labels {
			if podLabelKey == selKey && podLabelVal == selVal {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	return true
}

////////////////////////////// Service Related Handler Routines /////////////////////////

// GetServiceInfo : Get ServiceInfo for given service type
func (sp *SaseServiceProcessor) GetServiceInfo(svcInfo common.PodSaseServiceInfo) (*common.ServiceInfo, error) {

	info, ok := sp.services[svcInfo]
	if !ok {
		return nil, errors.New("GetServiceInfo: Service Info Not Found")
	}

	return info, nil

}

// processServiceAddition handles the event of adding new services on a given pod
// Add Service info in the services DB and invoke any init routine for the service if any
func (sp *SaseServiceProcessor) processServiceAddition(podID podmodel.ID, addService []common.PodSaseServiceInfo) error {

	for _, s := range addService {
		sp.Log.Info("processServiceAddition: ", s)
		service := &common.ServiceInfo{
			Name: s,
		}

		podInfo, err := sp.GetPodInfo(podID)
		if err != nil {
			return errors.New("processServiceAddition: CNF Pod Not found")
		}

		sp.Log.Info("processServiceAddition: Add PodInfo to Service")
		service.Pod = podInfo

		sp.Log.Info("processServiceAddition: Add Service to Services Map")
		// Add service info in service cache
		sp.services[s] = service

		sp.Log.Info("processServiceAddition: Add Service to Pod Service List", s)
		// Add service details to podsList servicelist cache
		sp.podsList[podID].AddSaseServiceInfo(s)

		// Get service type
		serviceType := service.GetServiceType()

		sp.Log.Info("processServiceAddition: Render ", service.Name, "service Init")
		// Init Service
		sp.renderers[serviceType].Init()
	}
	return nil
}

// processUpdatedPodCustomIfs handles the event of updating pod custom interfaces.
// Delete Service info from the services DB and invoke any de-init routine for the service if any
func (sp *SaseServiceProcessor) processServiceDeletion(podID podmodel.ID, delService []common.PodSaseServiceInfo) error {

	for _, s := range delService {

		sp.Log.Info("processServiceDeletion: ", s)

		if _, ok := sp.services[s]; ok {
			// Get Service Type
			serviceType := sp.services[s].GetServiceType()

			sp.Log.Info("processServiceDeletion: Render ", sp.services[s].Name, "service DeInit")
			// De-Init service
			sp.renderers[serviceType].DeInit()

			sp.Log.Info("processServiceDeletion: Delete Service from services list")
			// Delete Service from the service cache
			delete(sp.services, s)
		}

		sp.Log.Info("processServiceDeletion: Delete Service from PodInfo")
		// Delete service info from Pods service list cache
		sp.podsList[podID].DeleteSaseServiceInfo(s)
	}

	return nil
}

// ProcessCustomIfIPAlloc Handle IP address assignments for Pod Custom Interfaces
// that have references to customnetwork config
func (sp *SaseServiceProcessor) ProcessCustomIfIPAlloc(alloc *ipalloc.CustomIPAllocation) error {
	sp.Log.WithFields(logging.Fields{
		"alloc": alloc,
	}).Debug("ProcessCustomIfIPAlloc()")

	// Update Pod Interface Cache
	podID := podmodel.ID{
		Name:      alloc.PodName,
		Namespace: alloc.PodNamespace}

	podInfo, ok := sp.podsList[podID]
	if !ok {
		return errors.New("ProcessCustomIfIPAlloc: Pod not found in the podList")
	}

	// Update IP addresses for the Pod Interfaces
	for _, customIf := range alloc.CustomInterfaces {
		podInfo.UpdateInterfaceIP(customIf.Name, customIf.IpAddress, customIf.Network)
	}

	sp.Log.Infof("ProcessCustomIfIPAlloc: Updated Interface IP %v", sp.podsList[podID])
	return nil
}

// getPodUpdateServiceList :
func getPodUpdateServiceList(newList, existingList []common.PodSaseServiceInfo) (addService []common.PodSaseServiceInfo, delService []common.PodSaseServiceInfo) {
	serviceMap := make(map[common.PodSaseServiceInfo]bool, len(existingList))
	for _, serviceInfo := range existingList {
		serviceMap[serviceInfo] = true
	}

	for _, service := range newList {
		if _, found := serviceMap[service]; !found {
			addService = append(addService, service)
		}
		//
		delete(serviceMap, service)
	}

	for key := range serviceMap {
		delService = append(delService, key)
	}

	return addService, delService
}
