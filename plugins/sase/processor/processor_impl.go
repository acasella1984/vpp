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
)

// SaseProcessor implements SaseProcessorAPI.
type SaseProcessor struct {
	Deps
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
func (sp *SaseProcessor) Init() error {
	sp.Log.Debug("Sase Processor Init")
	return nil
}

// reset (re)initializes all internal maps.
func (sp *SaseProcessor) reset() {
}

// AfterInit does nothing for the SFC processor.
func (sp *SaseProcessor) AfterInit() error {
	return nil
}

// Update is called for:
//  - KubeStateChange for Sase-related config
func (sp *SaseProcessor) Update(event controller.Event) error {
	sp.Log.Infof("Update: %v", event)
	if k8sChange, isK8sChange := event.(*controller.KubeStateChange); isK8sChange {
		switch k8sChange.Resource {
		case sasemodel.Keyword:
			if k8sChange.NewValue != nil {
				// Get the Sase Model Config Data.
				saseCfg := k8sChange.NewValue.(*sasemodel.SaseConfig)
				if k8sChange.PrevValue == nil {
					return sp.processNewSaseServiceConfig(saseCfg)
				}
				return sp.processUpdateSaseServiceConfig(saseCfg)
			}
			saseDelCfg := k8sChange.PrevValue.(*sasemodel.SaseConfig)
			return sp.processDeletedSaseServiceConfig(saseDelCfg)
		default:
		}
	}

	return nil
}

// Resync processes a resync event.
// The cache content is fully replaced and all registered renderers
// receive a full snapshot of Contiv SFCs at the present state to be (re)installed.
func (sp *SaseProcessor) Resync(kubeStateData controller.KubeStateData) error {

	return nil
}

// Close does nothing for the Sase processor.
func (sp *SaseProcessor) Close() error {
	return nil
}

//////////////////////////////// Sase Config Processor Routines ////////////////////////

// processNewSaseServiceConfig
func (sp *SaseProcessor) processNewSaseServiceConfig(cfg *sasemodel.SaseConfig) error {
	sp.Log.Infof("processNewSaseServiceConfig: %v", cfg)
	return nil
}

// processUpdateSaseServiceConfig
func (sp *SaseProcessor) processUpdateSaseServiceConfig(cfg *sasemodel.SaseConfig) error {
	sp.Log.Infof("processUpdateSaseServiceConfig: %v", cfg)
	return nil
}

// processDeletedSaseServiceConfig
func (sp *SaseProcessor) processDeletedSaseServiceConfig(cfg *sasemodel.SaseConfig) error {
	sp.Log.Infof("processDeletedSaseServiceConfig: %v", cfg)
	return nil
}

// processNewPod handles the event of adding of a new pod.
func (sp *SaseProcessor) processNewPod(pod *podmodel.Pod) error {
	return sp.processUpdatedPod(pod)
}

// processUpdatedPod handles the event of updating runtime state of a pod.
func (sp *SaseProcessor) processUpdatedPod(pod *podmodel.Pod) error {
	// ignore pods without IP (not yet scheduled)
	if pod.IpAddress == "" {
		return nil
	}

	sp.Log.Debugf("New / Updated pod: %v", pod)

	podData := sp.PodManager.GetPods()[podmodel.GetID(pod)]
	if podData == nil {
		return nil
	}

	return nil
}

// processDeletedPod handles the event of deletion of a pod.
func (sp *SaseProcessor) processDeletedPod(pod *podmodel.Pod) error {

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
func (sp *SaseProcessor) processUpdatedPodCustomIfs(pod *ipnet.PodCustomIfUpdate) error {

	podData := sp.PodManager.GetPods()[pod.PodID]
	if podData == nil {
		return nil
	}
	sp.Log.Debugf("Update pod custom ifs: %v", podData)
	return nil
}

// podMatchesSelector returns true if the pod matches provided label selector, false otherwise.
func (sp *SaseProcessor) podMatchesSelector(pod *podmanager.Pod, podSelector map[string]string) bool {
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
