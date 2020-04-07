package renderer

import (
	"fmt"

	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/sase/config"
	"github.com/gogo/protobuf/proto"
	"go.ligato.io/cn-infra/v2/db/keyval"
	"go.ligato.io/cn-infra/v2/servicelabel"
)

// SaseServiceRendererAPI defines the APIs for Sase Service rendering.
type SaseServiceRendererAPI interface {

	// Renderer Init
	Init() error

	// Renderer DeInit
	DeInit() error

	// Renderer AfterInit
	AfterInit() error

	// AddServiceConfig
	AddServiceConfig(sp *config.SaseServiceConfig, reSync bool) error

	// UpdateServiceConfig
	UpdateServiceConfig(old, new *config.SaseServiceConfig) error

	// DeleteServiceConfig
	DeleteServiceConfig(sp *config.SaseServiceConfig) error

}

// Commit to remote persistent DB
func Commit(remotedb nodesync.KVDBWithAtomic, serviceLabel string, key string, value proto.Message, eventType config.EventType) error {

	// Get the broker instance for the given serviceLabel
	broker := remotedb.NewBrokerWithAtomic(servicelabel.GetDifferentAgentPrefix(serviceLabel))
	serializer := keyval.SerializerJSON{}
	binData, err := serializer.Marshal(value)
	if err != nil {
		return err
	}
	if eventType != config.Delete {
		_, err = broker.PutIfNotExists(key, binData)
		if err != nil {
			return err
		}
	} else {
		_, err = broker.Delete(key)
	}
	return err
}

// MockCommit : Used for Testing
func MockCommit(serviceLabel string, key string, value proto.Message, eventType config.EventType) error {

	fmt.Println("ServiceLabel: ", serviceLabel, "key: ", key, "Value: ", value, "eventType: ", eventType)
	return nil
}
