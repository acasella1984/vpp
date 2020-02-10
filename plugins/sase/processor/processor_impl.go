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
	"github.com/contiv/vpp/plugins/sase/renderer"
)

// SaseServiceProcessor implements SaseProcessorAPI.
type SaseServiceProcessor struct {
	Deps
	renderers map[sasemodel.SaseConfig_SaseService]renderer.SaseServiceRendererAPI

	// Maintain local cache of all the sase service policies that are applied
	// Housekeeping stuff
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
	sp.renderers = make(map[sasemodel.SaseConfig_SaseService]renderer.SaseServiceRendererAPI)
	return nil
}

// reset (re)initializes all internal maps.
func (sp *SaseServiceProcessor) reset() {
}

// RegisterRenderer register sase service renderers
func (sp *SaseServiceProcessor) RegisterRenderer(name sasemodel.SaseConfig_SaseService,
	renderer renderer.SaseServiceRendererAPI) error {

	// register renderer
	sp.renderers[name] = renderer
	return nil
}

// GetRenderer returns sase service renderers identified by the name
func (sp *SaseServiceProcessor) GetRenderer(name sasemodel.SaseConfig_SaseService) (renderer.SaseServiceRendererAPI, error) {

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
		case sasemodel.Keyword:
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

//////////////////////////////// Sase Config Processor Routines ////////////////////////

// processNewSaseServiceConfig
func (sp *SaseServiceProcessor) processNewSaseServiceConfig(cfg *sasemodel.SaseConfig) error {
	sp.Log.Infof("processNewSaseServiceConfig: %v", cfg)

	// Get Pod that is running the Sase service. A CNF Pod may be supportingg  multiple
	// sase services. TBD

	// Get Pod Data which would include the interfaces and other relevant information

	// Get Pod Microservice Label

	// Fill in the relevant information
	p := &renderer.SaseServicePolicy{}
	// Get the type of Sase Service
	saseService := cfg.GetSaseService()
	rndr, err := sp.GetRenderer(saseService)
	if err != nil {
		return err
	}
	err = rndr.AddPolicy(p)
	return err
}

// processUpdateSaseServiceConfig
func (sp *SaseServiceProcessor) processUpdateSaseServiceConfig(old, new *sasemodel.SaseConfig) error {
	sp.Log.Infof("processUpdateSaseServiceConfig: old: %v new: %v", old, new)
	// Get Pod that is running the Sase service. A CNF Pod may be supportingg  multiple
	// sase services. TBD

	// Get Pod Data which would include the interfaces and other relevant information

	// Get Pod Microservice Label

	// Fill in the relevant information
	oldP := &renderer.SaseServicePolicy{}
	newP := &renderer.SaseServicePolicy{}
	// Get the type of Sase Service
	saseService := new.GetSaseService()
	rndr, err := sp.GetRenderer(saseService)
	if err != nil {
		return err
	}
	err = rndr.UpdatePolicy(oldP, newP)
	return err
}

// processDeletedSaseServiceConfig
func (sp *SaseServiceProcessor) processDeletedSaseServiceConfig(cfg *sasemodel.SaseConfig) error {
	sp.Log.Infof("processDeletedSaseServiceConfig: %v", cfg)
	// Get Pod that is running the Sase service. A CNF Pod may be supportingg  multiple
	// sase services. TBD

	// Get Pod Data which would include the interfaces and other relevant information

	// Get Pod Microservice Label

	// Fill in the relevant information
	p := &renderer.SaseServicePolicy{}
	// Get the type of Sase Service
	saseService := cfg.GetSaseService()
	rndr, err := sp.GetRenderer(saseService)
	if err != nil {
		return err
	}
	err = rndr.DeletePolicy(p)
	return err
}

// processNewPod handles the event of adding of a new pod.
func (sp *SaseServiceProcessor) processNewPod(pod *podmodel.Pod) error {
	return sp.processUpdatedPod(pod)
}

// processUpdatedPod handles the event of updating runtime state of a pod.
func (sp *SaseServiceProcessor) processUpdatedPod(pod *podmodel.Pod) error {
	// ignore pods without IP (not yet scheduled)
	if pod.IpAddress == "" {
		return nil
	}

	sp.Log.Infof("New / Updated pod: %v", pod)

	podData := sp.PodManager.GetPods()[podmodel.GetID(pod)]
	if podData == nil {
		return nil
	}

	if hasSaseServicesAnnotation(pod.Annotations) == true {
		saseServices := getSaseServices(pod.Annotations)

		for _, saseService := range saseServices {
			saseServiceInfo, _ := parseSaseServiceName(saseService)
			sp.Log.Infof("New / Updated pod: SaseServiceInfo %v", saseServiceInfo)
		}
	}

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
