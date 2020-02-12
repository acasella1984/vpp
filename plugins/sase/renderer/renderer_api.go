package renderer

import (
	sasemodel "github.com/contiv/vpp/plugins/crd/handler/saseconfig/model"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/sase/common"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/servicelabel"
)

// SaseServiceRendererAPI defines the APIs for Sase Service rendering.
type SaseServiceRendererAPI interface {

	// Renderer Init
	Init() error

	// Renderer DeInit
	DeInit() error

	// Renderer AfterInit
	AfterInit() error

	// AddPolicy
	AddPolicy(sp *SaseServiceConfig) error

	// UpdatePolicy
	UpdatePolicy(old, new *SaseServiceConfig) error

	// DeletePolicy
	DeletePolicy(sp *SaseServiceConfig) error

	// Resync provides a complete snapshot of all service function chain-related data.
	// The renderer should resolve any discrepancies between the state of SFC in K8s
	// and the currently rendered configuration.
}

// SaseServiceConfig is common abstraction which contains neccessary information that would be
// required by renderer to render the config into dataplane
type SaseServiceConfig struct {
	// Service Info
	ServiceInfo *common.ServiceInfo
	// Policy Details
	Policy *sasemodel.SaseConfig
	// Security Associations
	SecurityAssociation *sasemodel.SecurityAssociation
	// Site Resource Group
	SiteResourceGroup *sasemodel.SiteResourceGroup
	// IPSecVpnTunnel
	IPSecVpnTunnel *sasemodel.IPSecVpnTunnel
}

// Interface : Nat Interface
// Local inside Interface (true) or external Public Interface (false)
// Twice Nat Enabled (true)
type Interface struct {
	Name     string
	IsLocal  bool
	TwiceNat bool
}

// Subnets : Subnet Addresses
type Subnets struct {
	Vrf    uint32
	Subnet string
	// Any other attributes here for the given subnet??
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

// ProtocolType is either TCP or UDP or OTHER.
type ProtocolType int

const (
	// TCP protocol.
	TCP ProtocolType = iota
	// UDP protocol.
	UDP
	// ESP Protocol
	ESP
	// OTHER is some NON-UDP, NON-TCP traffic (used ONLY in unit tests).
	OTHER
	// ANY L4 protocol or even pure L3 traffic (port numbers are ignored).
	ANY
)

// String converts ProtocolType into a human-readable string.
func (at ProtocolType) String() string {
	switch at {
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	case OTHER:
		return "OTHER"
	case ANY:
		return "ANY"
	}
	return "INVALID"
}

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
