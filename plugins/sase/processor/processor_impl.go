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

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/servicelabel"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	sasemodel "github.com/contiv/vpp/plugins/crd/handler/saseconfig/model"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/contiv/vpp/plugins/sase/common"
	"github.com/contiv/vpp/plugins/sase/config"
	"github.com/contiv/vpp/plugins/sase/renderer"
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
					return sp.processNewSaseServiceConfig(saseNewCfg)
				}
				sasePrevCfg := k8sChange.NewValue.(*sasemodel.SaseConfig)
				return sp.processUpdateSaseServiceConfig(sasePrevCfg, saseNewCfg)
			}
			saseDelCfg := k8sChange.PrevValue.(*sasemodel.SaseConfig)
			return sp.processDeletedSaseServiceConfig(saseDelCfg)
		case sasemodel.SecurityAssociationKey:
			if k8sChange.NewValue != nil {
				// Get the Security Association Config Data.
				saNewCfg := k8sChange.NewValue.(*sasemodel.SecurityAssociation)
				if k8sChange.PrevValue == nil {
					return sp.processNewSecurityAssociationConfig(saNewCfg)
				}
				saPrevCfg := k8sChange.NewValue.(*sasemodel.SecurityAssociation)
				return sp.processUpdateSecurityAssociationConfig(saPrevCfg, saNewCfg)
			}
			saDelCfg := k8sChange.PrevValue.(*sasemodel.SecurityAssociation)
			return sp.processDeletedSecurityAssociationConfig(saDelCfg)
		case sasemodel.SiteResourceGroupKey:
			if k8sChange.NewValue != nil {
				// Get the Site Resource Config Data.
				srNewCfg := k8sChange.NewValue.(*sasemodel.SiteResourceGroup)
				if k8sChange.PrevValue == nil {
					return sp.processNewSiteResourceConfig(srNewCfg)
				}
				srPrevCfg := k8sChange.NewValue.(*sasemodel.SiteResourceGroup)
				return sp.processUpdateSiteResourceConfig(srPrevCfg, srNewCfg)
			}
			srDelCfg := k8sChange.PrevValue.(*sasemodel.SiteResourceGroup)
			return sp.processDeletedSiteResourceConfig(srDelCfg)
		case sasemodel.IPSecVpnTunnelKey:
			if k8sChange.NewValue != nil {
				// Get the IpSec VPN Tunnel Config Data.
				ipsecNewCfg := k8sChange.NewValue.(*sasemodel.IPSecVpnTunnel)
				if k8sChange.PrevValue == nil {
					return sp.processNewIPSecVpnTunnelConfig(ipsecNewCfg)
				}
				ipsecPrevCfg := k8sChange.NewValue.(*sasemodel.IPSecVpnTunnel)
				return sp.processUpdateIPSecVpnTunnelConfig(ipsecPrevCfg, ipsecNewCfg)
			}
			ipsecDelCfg := k8sChange.PrevValue.(*sasemodel.IPSecVpnTunnel)
			return sp.processDeletedIPSecVpnTunnelConfig(ipsecDelCfg)
		case podmodel.PodKeyword:
			if k8sChange.NewValue != nil {
				pod := k8sChange.NewValue.(*podmodel.Pod)
				if k8sChange.PrevValue == nil {
					return sp.processNewPod(pod)
				}
				return sp.processUpdatedPod(pod)
			}
			pod := k8sChange.PrevValue.(*podmodel.Pod)
			return sp.processDeletedPod(pod)
		default:
		}
	}

	return nil
}

// Resync processes a resync event.
// The cache content is fully replaced and all registered renderers
// receive a full snapshot of Contiv SFCs at the present state to be (re)installed.
func (sp *SaseServiceProcessor) Resync(kubeStateData controller.KubeStateData) error {

	return nil
}

// Close does nothing for the Sase processor.
func (sp *SaseServiceProcessor) Close() error {
	return nil
}

//////////////////////////////// Sase Policies Processor Routines ////////////////////////

// processNewSaseServiceConfig
func (sp *SaseServiceProcessor) processNewSaseServiceConfig(cfg *sasemodel.SaseConfig) error {
	sp.Log.Infof("processNewSaseServiceConfig: %v", cfg)

	s, _ := common.ParseSaseServiceName(cfg.SaseServiceName)
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
	err = rndr.AddServiceConfig(p)
	return err
}

// processUpdateSaseServiceConfig
func (sp *SaseServiceProcessor) processUpdateSaseServiceConfig(old, new *sasemodel.SaseConfig) error {
	sp.Log.Infof("processUpdateSaseServiceConfig: old: %v new: %v", old, new)
	s, _ := common.ParseSaseServiceName(new.SaseServiceName)
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

// processDeletedSaseServiceConfig
func (sp *SaseServiceProcessor) processDeletedSaseServiceConfig(cfg *sasemodel.SaseConfig) error {
	sp.Log.Infof("processDeletedSaseServiceConfig: %v", cfg)
	s, _ := common.ParseSaseServiceName(cfg.SaseServiceName)
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

//////////////////////////////// Site Resource Group Processor Routines ////////////////////////

// processNewSiteResourceConfig
// Site Resource Group consists of local and public networks and any other relevant resource information
// within a site.
func (sp *SaseServiceProcessor) processNewSiteResourceConfig(cfg *sasemodel.SiteResourceGroup) error {
	sp.Log.Infof("processNewSiteResourceConfig: %v", cfg)
	return nil
}

// processUpdateSiteResourceConfig
func (sp *SaseServiceProcessor) processUpdateSiteResourceConfig(old, new *sasemodel.SiteResourceGroup) error {
	sp.Log.Infof("processUpdateSiteResourceConfig: old: %v new: %v", old, new)
	return nil
}

// processDeletedSiteResourceConfig
func (sp *SaseServiceProcessor) processDeletedSiteResourceConfig(cfg *sasemodel.SiteResourceGroup) error {
	sp.Log.Infof("processDeletedSiteResourceConfig: %v", cfg)
	return nil
}

//////////////////////////////// Security Association Processor Routines ////////////////////////

// processNewSecurityAssociationConfig
func (sp *SaseServiceProcessor) processNewSecurityAssociationConfig(cfg *sasemodel.SecurityAssociation) error {
	sp.Log.Infof("processNewSecurityAssociationConfig: %v", cfg)
	return nil
}

// processUpdateSecurityAssociationConfig
func (sp *SaseServiceProcessor) processUpdateSecurityAssociationConfig(old, new *sasemodel.SecurityAssociation) error {
	sp.Log.Infof("processUpdateSecurityAssociationConfig: old: %v new: %v", old, new)
	return nil
}

// processDeletedSecurityAssociationConfig
func (sp *SaseServiceProcessor) processDeletedSecurityAssociationConfig(cfg *sasemodel.SecurityAssociation) error {
	sp.Log.Infof("processDeletedSecurityAssociationConfig: %v", cfg)
	return nil
}

//////////////////////////////// IPSec Vpn Tunnel Processor Routines ////////////////////////

// processNewIPSecVpnTunnelConfig
func (sp *SaseServiceProcessor) processNewIPSecVpnTunnelConfig(cfg *sasemodel.IPSecVpnTunnel) error {
	sp.Log.Infof("processNewSiteResourceConfig: %v", cfg)
	return nil
}

// processUpdateIPSecVpnTunnelConfig
func (sp *SaseServiceProcessor) processUpdateIPSecVpnTunnelConfig(old, new *sasemodel.IPSecVpnTunnel) error {
	sp.Log.Infof("processUpdateSiteResourceConfig: old: %v new: %v", old, new)
	return nil
}

// processDeletedIPSecVpnTunnelConfig
func (sp *SaseServiceProcessor) processDeletedIPSecVpnTunnelConfig(cfg *sasemodel.IPSecVpnTunnel) error {
	sp.Log.Infof("processDeletedSiteResourceConfig: %v", cfg)
	return nil
}

/////////////////////////// Pod Events ////////////////////////////////////////////

// processNewPod handles the event of adding of a new pod.
func (sp *SaseServiceProcessor) processNewPod(pod *podmodel.Pod) error {
	return sp.processUpdatedPod(pod)
}

// processUpdatedPod handles the event of updating runtime state of a pod.
// Service Add/Delete intent can be sent via Pod annotations and actions
// corresponding to Service Addition, Deletion to be taken.
func (sp *SaseServiceProcessor) processUpdatedPod(pod *podmodel.Pod) error {
	// ignore pods without IP (not yet scheduled)
	if pod.IpAddress == "" {
		return nil
	}

	sp.Log.Infof("New / Updated pod: %v", pod)

	podID := podmodel.GetID(pod)
	podData := sp.PodManager.GetPods()[podID]
	if podData == nil {
		return nil
	}

	// Handle CNF Pod Microservice label annotations
	_, ok := sp.podsList[podID]
	if !ok {
		// New Pod Event
		// Housekeep Pod Information
		label := common.GetContivMicroserviceLabel(podData.Annotations)
		podInfo := &common.PodInfo{
			ID:    podID,
			Label: label,
			//Interfaces: - TBD
		}
		sp.podsList[podID] = podInfo
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
		sp.processServiceAddition(podID, newServices)
		sp.processServiceDeletion(podID, deletedServices)
	}

	// Handle CNF Pod interface updates

	return nil
}

// processDeletedPod handles the event of deletion of a pod.
func (sp *SaseServiceProcessor) processDeletedPod(pod *podmodel.Pod) error {

	// construct pod info from k8s data (already deleted in PodManager)
	podData := &podmanager.Pod{
		ID:          podmodel.GetID(pod),
		IPAddress:   pod.IpAddress,
		Labels:      pod.Labels,
		Annotations: pod.Annotations,
	}
	sp.Log.Debugf("Delete pod: %v", podData)

	// Cleanup Service related information on Pod Delete trigger.
	// Service existence no longer relevant when Pod is deleted
	sp.processServiceDeletion(podData.ID, sp.podsList[podData.ID].ServiceList)
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

// processServiceAddition handles the event of adding new services on a given pod
// Add Service info in the services DB and invoke any init routine for the service if any
func (sp *SaseServiceProcessor) processServiceAddition(podID podmodel.ID, addService []common.PodSaseServiceInfo) error {

	for _, s := range addService {
		service := &common.ServiceInfo{
			Name: s,
			Pod:  sp.podsList[podID],
		}
		// Add service info in service cache
		sp.services[s] = service

		// Add service details to podsList servicelist cache
		sp.podsList[podID].ServiceList = append(sp.podsList[podID].ServiceList, s)

		// Get service type
		serviceType := service.GetServiceType()

		// Init Service
		sp.renderers[serviceType].Init()
	}
	return nil
}

// processUpdatedPodCustomIfs handles the event of updating pod custom interfaces.
// Delete Service info from the services DB and invoke any de-init routine for the service if any
func (sp *SaseServiceProcessor) processServiceDeletion(podID podmodel.ID, delService []common.PodSaseServiceInfo) error {
	for _, s := range delService {

		// Get Service Type
		serviceType := sp.services[s].GetServiceType()

		// De-Init service
		sp.renderers[serviceType].DeInit()

		// Delete service info from Pods service list cache
		for i := len(sp.podsList[podID].ServiceList) - 1; i >= 0; i-- {
			if s == sp.podsList[podID].ServiceList[i] {
				sp.podsList[podID].ServiceList = append(sp.podsList[podID].ServiceList[:i], sp.podsList[podID].ServiceList[i+1:]...)
			}
		}
		// Delete Service from the service cache
		delete(sp.services, s)
	}

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
