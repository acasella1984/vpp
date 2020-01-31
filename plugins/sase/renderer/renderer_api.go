package renderer

import (
	sasemodel "github.com/contiv/vpp/plugins/crd/handler/saseconfig/model"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/servicelabel"
)

// SaseServiceRendererAPI defines the APIs for Sase Service rendering.
type SaseServiceRendererAPI interface {

	// Renderer Init
	Init() error

	// Renderer AfterInit
	AfterInit() error

	// AddPolicy
	AddPolicy(sp *SaseServicePolicy) error

	// UpdatePolicy
	UpdatePolicy(old, new *SaseServicePolicy) error

	// DeletePolicy
	DeletePolicy(sp *SaseServicePolicy) error

	// Resync provides a complete snapshot of all service function chain-related data.
	// The renderer should resolve any discrepancies between the state of SFC in K8s
	// and the currently rendered configuration.
}

// SaseServicePolicy is common abstraction which contains neccessary information to be consumed
// by rendering services
type SaseServicePolicy struct {
	// Pod details to where service is running
	// This is to derive relevant information to render the policy
	// eg. Microservice Label, Interfaces, IPAddress

	// Policy Details
	policy *sasemodel.SaseConfig
}

// ConfigEventType represents the type of an configuration event processed by the ipnet plugin
type ConfigEventType int

const (
	// ConfigResync synchronization of the existing config vs demanded config
	ConfigResync ConfigEventType = iota
	// ConfigAdd addition of new config
	ConfigAdd
	// ConfigDelete deletion of existing config
	ConfigDelete
)

// Commit to remote persistent DB
func Commit(remotedb nodesync.KVDBWithAtomic, serviceLabel string, key string, value proto.Message, eventType ConfigEventType) error {

	// Get the broker instance for the given serviceLabel
	broker := remotedb.NewBrokerWithAtomic(servicelabel.GetDifferentAgentPrefix(serviceLabel))
	serializer := keyval.SerializerJSON{}
	binData, err := serializer.Marshal(value)
	if err != nil {
		return err
	}
	if eventType != ConfigDelete {
		_, err = broker.PutIfNotExists(key, binData)
		if err != nil {
			return err
		}
	} else {
		_, err = broker.Delete(key)
	}
	return err
}
