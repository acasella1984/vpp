package renderer

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
}
