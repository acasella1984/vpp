// Copyright (c) 2018 Cisco and/or its affiliates.
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

// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/contiv/vpp/plugins/crd/pkg/apis/contivppio/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// SaseServiceInterfaceLister helps list SaseServiceInterfaces.
type SaseServiceInterfaceLister interface {
	// List lists all SaseServiceInterfaces in the indexer.
	List(selector labels.Selector) (ret []*v1.SaseServiceInterface, err error)
	// SaseServiceInterfaces returns an object that can list and get SaseServiceInterfaces.
	SaseServiceInterfaces(namespace string) SaseServiceInterfaceNamespaceLister
	SaseServiceInterfaceListerExpansion
}

// saseServiceInterfaceLister implements the SaseServiceInterfaceLister interface.
type saseServiceInterfaceLister struct {
	indexer cache.Indexer
}

// NewSaseServiceInterfaceLister returns a new SaseServiceInterfaceLister.
func NewSaseServiceInterfaceLister(indexer cache.Indexer) SaseServiceInterfaceLister {
	return &saseServiceInterfaceLister{indexer: indexer}
}

// List lists all SaseServiceInterfaces in the indexer.
func (s *saseServiceInterfaceLister) List(selector labels.Selector) (ret []*v1.SaseServiceInterface, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.SaseServiceInterface))
	})
	return ret, err
}

// SaseServiceInterfaces returns an object that can list and get SaseServiceInterfaces.
func (s *saseServiceInterfaceLister) SaseServiceInterfaces(namespace string) SaseServiceInterfaceNamespaceLister {
	return saseServiceInterfaceNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// SaseServiceInterfaceNamespaceLister helps list and get SaseServiceInterfaces.
type SaseServiceInterfaceNamespaceLister interface {
	// List lists all SaseServiceInterfaces in the indexer for a given namespace.
	List(selector labels.Selector) (ret []*v1.SaseServiceInterface, err error)
	// Get retrieves the SaseServiceInterface from the indexer for a given namespace and name.
	Get(name string) (*v1.SaseServiceInterface, error)
	SaseServiceInterfaceNamespaceListerExpansion
}

// saseServiceInterfaceNamespaceLister implements the SaseServiceInterfaceNamespaceLister
// interface.
type saseServiceInterfaceNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all SaseServiceInterfaces in the indexer for a given namespace.
func (s saseServiceInterfaceNamespaceLister) List(selector labels.Selector) (ret []*v1.SaseServiceInterface, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.SaseServiceInterface))
	})
	return ret, err
}

// Get retrieves the SaseServiceInterface from the indexer for a given namespace and name.
func (s saseServiceInterfaceNamespaceLister) Get(name string) (*v1.SaseServiceInterface, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.Resource("saseserviceinterface"), name)
	}
	return obj.(*v1.SaseServiceInterface), nil
}
