// Copyright (c) 2019 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sase

import (
	"strings"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	sasemodel "github.com/contiv/vpp/plugins/crd/handler/saseconfig/model"
	"github.com/contiv/vpp/plugins/idalloc"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
	"github.com/contiv/vpp/plugins/sase/processor"
	"github.com/contiv/vpp/plugins/sfc/config"
	"github.com/contiv/vpp/plugins/statscollector"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/servicelabel"
	"github.com/ligato/vpp-agent/plugins/govppmux"
)

// Plugin watches configuration of K8s resources (as reflected by KSR+CRD into ETCD)
// for create and updates of sase service configuration and render them to vpp agent running
// the sase service .
type Plugin struct {
	Deps

	config *config.Config

	// ongoing transaction
	resyncTxn controller.ResyncOperations
	updateTxn controller.UpdateOperations
	changes   []string

	// layers of the sase plugin
	processor *processor.SaseProcessor
}

// Deps defines dependencies of the Sase plugin.
type Deps struct {
	infra.PluginDeps
	ServiceLabel    servicelabel.ReaderAPI
	ContivConf      contivconf.API
	IDAlloc         idalloc.API
	IPAM            ipam.API
	IPNet           ipnet.API
	NodeSync        nodesync.API
	PodManager      podmanager.API
	GoVPP           govppmux.API
	Stats           statscollector.API
	ConfigRetriever controller.ConfigRetriever
}

// Init initializes the Sase plugin and starts watching ETCD for K8s configuration.
func (p *Plugin) Init() error {
	// load configuration
	return nil
}

// AfterInit can be used by renderers to perform a second stage of initialization.
func (p *Plugin) AfterInit() error {
	return nil
}

// HandlesEvent selects:
//  - any resync event
//  - KubeStateChange for SFCs and pods
//  - pod custom interfaces update
//  - external interfaces update
func (p *Plugin) HandlesEvent(event controller.Event) bool {
	if event.Method() != controller.Update {
		return true
	}
	if ksChange, isKSChange := event.(*controller.KubeStateChange); isKSChange {
		switch ksChange.Resource {
		case sasemodel.Keyword:
			return true
		default:
			// unhandled Kubernetes state change
			return false
		}
	}
	// unhandled event
	return false
}

// Resync is called by Controller to handle event that requires full re-synchronization.
// For startup resync, resyncCount is 1. Higher counter values identify run-time resync.
func (p *Plugin) Resync(event controller.Event, kubeStateData controller.KubeStateData,
	resyncCount int, txn controller.ResyncOperations) error {

	p.resyncTxn = txn
	p.updateTxn = nil
	return p.processor.Resync(kubeStateData)
}

// Update is called for:
//  - KubeStateChange for Sase Services config updates
func (p *Plugin) Update(event controller.Event, txn controller.UpdateOperations) (changeDescription string, err error) {
	p.resyncTxn = nil
	p.updateTxn = txn
	p.changes = []string{}
	err = p.processor.Update(event)
	changeDescription = strings.Join(p.changes, ", ")
	return changeDescription, err
}

// Revert is NOOP.
func (p *Plugin) Revert(event controller.Event) error {
	return nil
}

// Close is NOOP.
func (p *Plugin) Close() error {
	return nil
}
