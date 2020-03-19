package processor_test

import (
	"testing"

	sasemodel "github.com/contiv/vpp/plugins/crd/handler/saseconfig/model"
	"github.com/contiv/vpp/plugins/ipam/ipalloc"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/sase/common"
	"github.com/contiv/vpp/plugins/sase/processor"
	firewallservice "github.com/contiv/vpp/plugins/sase/renderer/firewall"
	ipsecservice "github.com/contiv/vpp/plugins/sase/renderer/ipsec"
	natservice "github.com/contiv/vpp/plugins/sase/renderer/nat"
	routeservice "github.com/contiv/vpp/plugins/sase/renderer/route"
	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/cn-infra/v2/logging/logrus"
	. "github.com/onsi/gomega"
)

func initTest() *processor.SaseServiceProcessor {
	sSP := &processor.SaseServiceProcessor{}
	sSP.Log = logrus.DefaultLogger()
	sSP.Log.SetLevel(logging.DebugLevel)
	sSP.Log.Debug("common package")
	sSP.Init()

	// Register Renderers

	// NAT
	natR := &natservice.Renderer{
		Deps: natservice.Deps{
			Log:      sSP.Log,
			MockTest: true,
		},
	}

	// Firewall
	fireR := &firewallservice.Renderer{
		Deps: firewallservice.Deps{
			Log:      sSP.Log,
			MockTest: true,
		},
	}

	// ipsec
	ipsecR := &ipsecservice.Renderer{
		Deps: ipsecservice.Deps{
			Log:      sSP.Log,
			MockTest: true,
		},
	}

	// routing
	routeR := &routeservice.Renderer{
		Deps: routeservice.Deps{
			Log:      sSP.Log,
			MockTest: true,
		},
	}

	// Register renderer.
	sSP.RegisterRenderer(common.ServiceTypeNAT, natR)
	sSP.RegisterRenderer(common.ServiceTypeFirewall, fireR)
	sSP.RegisterRenderer(common.ServiceTypeIPSecVpn, ipsecR)
	sSP.RegisterRenderer(common.ServiceTypeRouting, routeR)

	// Register Base VPP vswitch pod and services
	sSP.BaseVppPodServiceInit()

	return sSP

}

func getCustomIPAM() *ipalloc.CustomIPAllocation {

	// IP Allocation for the pod custom ifs
	ipam := &ipalloc.CustomIPAllocation{
		PodName:      "vpp-cnf-all",
		PodNamespace: "default",
		CustomInterfaces: []*ipalloc.CustomPodInterface{&ipalloc.CustomPodInterface{
			Name:      "memif1",
			Network:   "default",
			IpAddress: "10.40.1.9",
		}, &ipalloc.CustomPodInterface{
			Name:      "memif2",
			Network:   "default",
			IpAddress: "10.40.1.10",
		}},
	}

	return ipam
}

func getNewPod() *podmodel.Pod {
	pod := &podmodel.Pod{
		Name:      "vpp-cnf-all",
		Namespace: "default",
		Label: []*podmodel.Pod_Label{&podmodel.Pod_Label{Key: "app",
			Value: "vpp-cnf-all"}},
		IpAddress:     "10.40.1.8",
		HostIpAddress: "10.0.2.15",
		Container:     []*podmodel.Pod_Container{&podmodel.Pod_Container{Name: "vpp-agent"}},
	}

	// Add Annotations
	pod.Annotations = make(map[string]string)
	// custom ifs
	pod.Annotations["contivpp.io/custom-if"] = "memif1/memif, memif2/memif"
	// services
	pod.Annotations["contivpp.io/sase-service"] = "1/sjc/ipsecvpn, 1/sjc/firewall, 1/sjc/nat, 1/sjc/routing"
	// microservice label
	pod.Annotations["contivpp.io/microservice-label"] = "vpp-cnf-all"

	//label
	pod.Labels = make(map[string]string)
	pod.Labels["app"] = "vpp-cnf-all"

	return pod
}

func getNewPodWithFirewallService() *podmodel.Pod {
	pod := &podmodel.Pod{
		Name:      "vpp-cnf-firewall",
		Namespace: "default",
		Label: []*podmodel.Pod_Label{&podmodel.Pod_Label{Key: "app",
			Value: "vpp-cnf-firewall"}},
		IpAddress:     "10.40.1.8",
		HostIpAddress: "10.0.2.15",
		Container:     []*podmodel.Pod_Container{&podmodel.Pod_Container{Name: "vpp-agent"}},
	}

	// Add Annotations
	pod.Annotations = make(map[string]string)
	// custom ifs
	pod.Annotations["contivpp.io/custom-if"] = "memif1/memif, memif2/memif"
	// services
	pod.Annotations["contivpp.io/sase-service"] = "1/sjc/firewall"
	// microservice label
	pod.Annotations["contivpp.io/microservice-label"] = "vpp-cnf-firewall"

	//label
	pod.Labels = make(map[string]string)
	pod.Labels["app"] = "vpp-cnf-firewall"

	return pod
}

func getCustomIPAMForNatPod() *ipalloc.CustomIPAllocation {

	// IP Allocation for the pod custom ifs
	ipam := &ipalloc.CustomIPAllocation{
		PodName:      "vpp-cnf-nat",
		PodNamespace: "default",
		CustomInterfaces: []*ipalloc.CustomPodInterface{&ipalloc.CustomPodInterface{
			Name:      "memif1",
			Network:   "default",
			IpAddress: "10.40.1.9",
		}, &ipalloc.CustomPodInterface{
			Name:      "memif2",
			Network:   "default",
			IpAddress: "10.40.1.10",
		}},
	}

	return ipam
}

func getNewPodWithNatService() *podmodel.Pod {
	pod := &podmodel.Pod{
		Name:      "vpp-cnf-nat",
		Namespace: "default",
		Label: []*podmodel.Pod_Label{&podmodel.Pod_Label{Key: "app",
			Value: "vpp-cnf-nat"}},
		IpAddress:     "10.40.1.8",
		HostIpAddress: "10.0.2.15",
		Container:     []*podmodel.Pod_Container{&podmodel.Pod_Container{Name: "vpp-agent"}},
	}

	// Add Annotations
	pod.Annotations = make(map[string]string)
	// custom ifs
	pod.Annotations["contivpp.io/custom-if"] = "memif1/memif, memif2/memif"
	// services
	pod.Annotations["contivpp.io/sase-service"] = "1/sjc/nat"
	// microservice label
	pod.Annotations["contivpp.io/microservice-label"] = "vpp-cnf-nat"

	//label
	pod.Labels = make(map[string]string)
	pod.Labels["app"] = "vpp-cnf-nat"

	return pod
}

func TestProcessorInit(t *testing.T) {
	RegisterTestingT(t)
	sSP := initTest()
	Expect(sSP).NotTo(BeNil())
}

/////////// Pod Event Tests //////////////////

func TestProcessorPodAdd(t *testing.T) {
	RegisterTestingT(t)
	sSP := initTest()
	Expect(sSP).NotTo(BeNil())
	Expect(sSP.ProcessNewPod(getNewPod())).To(BeNil())
}

func TestProcessorPodAddDel(t *testing.T) {
	RegisterTestingT(t)
	sSP := initTest()
	Expect(sSP).NotTo(BeNil())

	// Add New Pod
	Expect(sSP.ProcessNewPod(getNewPod())).To(BeNil())

	// Delete Pod
	Expect(sSP.ProcessDeletedPod(getNewPod())).To(BeNil())
}

func TestProcessorPodCustomIfIpAlloc(t *testing.T) {
	RegisterTestingT(t)
	sSP := initTest()
	Expect(sSP).NotTo(BeNil())

	// Add New Pod
	Expect(sSP.ProcessNewPod(getNewPod())).To(BeNil())

	// Send IP Alloc Event
	Expect(sSP.ProcessCustomIfIPAlloc(getCustomIPAM())).To(BeNil())
}

////////////// Sase config handling tests //////////////

func getSasePolicy(policyType string, serviceName string) *sasemodel.SaseConfig {

	var cfg *sasemodel.SaseConfig
	switch policyType {
	case "nat":
		cfg = getSasePolicyNat(serviceName)
	case "firewall":
		cfg = getSasePolicyFirewall(serviceName)
	}
	return cfg
}

func getSasePolicyNat(serviceName string) *sasemodel.SaseConfig {

	// Nat Policy
	natPolicy := &sasemodel.SaseConfig{
		Name:                "nat-config",
		ServiceInstanceName: serviceName,
		Match:               &sasemodel.SaseConfig_Match{},
		Action:              sasemodel.SaseConfig_SNAT,
	}

	return natPolicy
}

func getSasePolicyFirewall(serviceName string) *sasemodel.SaseConfig {

	// firewall Policy
	firewallPolicy := &sasemodel.SaseConfig{
		Name:                "firewall-config",
		ServiceInstanceName: serviceName,
		Match: &sasemodel.SaseConfig_Match{
			SourceIp:      "10.10.10.12/24",
			DestinationIp: "20.20.20.10/24",
			Protocol:      sasemodel.SaseConfig_Match_TCP,
			Port:          8080,
		},
		Action: sasemodel.SaseConfig_DENY,
	}

	return firewallPolicy
}

func TestProcessorSasePolicyWhenServiceNotEnabled(t *testing.T) {

	RegisterTestingT(t)
	sSP := initTest()
	Expect(sSP).NotTo(BeNil())

	// Test NAT Policy
	Expect(sSP.ProcessNewSaseServiceConfig(getSasePolicy("nat", "1/sjc/nat"))).NotTo(BeNil())

	// Test Firewall Policy
	Expect(sSP.ProcessNewSaseServiceConfig(getSasePolicy("firewall", "1/sjc/firewall"))).NotTo(BeNil())
}

func TestProcessorSasePolicyWithNatServicePod(t *testing.T) {

	RegisterTestingT(t)
	sSP := initTest()
	Expect(sSP).NotTo(BeNil())

	// Add New Pod with Nat Service enabled
	Expect(sSP.ProcessNewPod(getNewPodWithNatService())).To(BeNil())

	// Send IP Alloc Event
	Expect(sSP.ProcessCustomIfIPAlloc(getCustomIPAMForNatPod())).To(BeNil())

	// Test Adding NAT Policy
	Expect(sSP.ProcessNewSaseServiceConfig(getSasePolicy("nat", "1/sjc/nat"))).To(BeNil())

	// Test Update Firewall Policy- TBD

	// Test Deleting NAT Policy
	Expect(sSP.ProcessDeletedSaseServiceConfig(getSasePolicy("nat", "1/sjc/nat"))).To(BeNil())
}

func TestProcessorSasePolicyWithFirewallServicePod(t *testing.T) {

	RegisterTestingT(t)
	sSP := initTest()
	Expect(sSP).NotTo(BeNil())

	// Add New Pod with Firewall Service enabled
	Expect(sSP.ProcessNewPod(getNewPodWithFirewallService())).To(BeNil())

	// Test Firewall Policy
	Expect(sSP.ProcessNewSaseServiceConfig(getSasePolicy("firewall", "1/sjc/firewall"))).To(BeNil())

	// Test Update Firewall Policy - TBD

	// Test Deleting Firewall Policy
	Expect(sSP.ProcessDeletedSaseServiceConfig(getSasePolicy("firewall", "1/sjc/firewall"))).To(BeNil())
}

func TestProcessorSasePolicyMultiServiceOneCNFPod(t *testing.T) {

	RegisterTestingT(t)
	sSP := initTest()
	Expect(sSP).NotTo(BeNil())

	// Add New Pod with All Services enabled
	Expect(sSP.ProcessNewPod(getNewPod())).To(BeNil())

	// Test Adding NAT Policy
	Expect(sSP.ProcessNewSaseServiceConfig(getSasePolicy("nat", "1/sjc/nat"))).To(BeNil())

	// Test Adding Firewall Policy
	Expect(sSP.ProcessNewSaseServiceConfig(getSasePolicy("firewall", "1/sjc/firewall"))).To(BeNil())

	// Test Deleting NAT Policy
	Expect(sSP.ProcessDeletedSaseServiceConfig(getSasePolicy("nat", "1/sjc/nat"))).To(BeNil())

	// Test Deleting Firewall Policy
	Expect(sSP.ProcessDeletedSaseServiceConfig(getSasePolicy("firewall", "1/sjc/firewall"))).To(BeNil())
}

func TestProcessorSasePolicyWithMultiServiceMultiCNFPod(t *testing.T) {

	RegisterTestingT(t)
	sSP := initTest()
	Expect(sSP).NotTo(BeNil())

	// Add New Pod with Nat Service enabled
	Expect(sSP.ProcessNewPod(getNewPodWithNatService())).To(BeNil())
	// Test NAT Policy
	Expect(sSP.ProcessNewSaseServiceConfig(getSasePolicy("nat", "1/sjc/nat"))).To(BeNil())

	// Add New Pod with Firewall Service enabled
	Expect(sSP.ProcessNewPod(getNewPodWithFirewallService())).To(BeNil())
	// Test Firewall Policy
	Expect(sSP.ProcessNewSaseServiceConfig(getSasePolicy("firewall", "1/sjc/firewall"))).To(BeNil())

}

// Security Association Config Test
func getConfigSecurityAssociation() *sasemodel.SecurityAssociation {

	// Security Association
	sa := &sasemodel.SecurityAssociation{
		Name:                "default-sa",
		ServiceInstanceName: "1/sjc/ipsecvpn",
		AuthAlgorithm:       "sha1-96",
		AuthSharedKey:       "4339314b55523947594d6d3547666b45764e6a58",
		EncryptAlgorithm:    "aes-cbc-128",
		EncryptSharedKey:    "4a506a794f574265564551694d653768",
	}

	return sa
}
func TestProcessorSecurityAssociation(t *testing.T) {

	RegisterTestingT(t)
	sSP := initTest()
	Expect(sSP).NotTo(BeNil())

	// Add New Pod with ipsec vpn service
	Expect(sSP.ProcessNewPod(getNewPod())).To(BeNil())

	// Test Creation of Security Group
	Expect(sSP.ProcessNewSecurityAssociationConfig(getConfigSecurityAssociation())).To(BeNil())

	// Test Update Firewall Policy - TBD

	// Test Deletion of Security Group
	Expect(sSP.ProcessDeletedSecurityAssociationConfig(getConfigSecurityAssociation())).To(BeNil())

}

// Site Resource Group Config Test
func getConfigSiteResourceGroup() *sasemodel.SiteResourceGroup {

	// Site Resource Group
	srg := &sasemodel.SiteResourceGroup{}

	return srg
}
func TestProcessorSiteResourceGroup(t *testing.T) {
	RegisterTestingT(t)

}

// IPSec VPN Tunnel Config Test
func getConfigIPSecVpnTunnel() *sasemodel.IPSecVpnTunnel {

	// IPSec VPN tunnel
	ipsec := &sasemodel.IPSecVpnTunnel{
		TunnelName:          "sjc-blr-tunnel",
		ServiceInstanceName: "1/sjc/ipsecvpn",
		TunnelDestinationIp: "6.6.6.1",
		TunnelSourceIp:      "5.5.5.1",
		SecurityAssociation: "default-sa",
	}

	return ipsec
}

func TestProcessorIPSecVpnTunnel(t *testing.T) {

	RegisterTestingT(t)
	sSP := initTest()
	Expect(sSP).NotTo(BeNil())

	// Add New Pod with ipsec vpn service
	Expect(sSP.ProcessNewPod(getNewPod())).To(BeNil())

	// IPSec VPN tunnel creation
	Expect(sSP.ProcessNewIPSecVpnTunnelConfig(getConfigIPSecVpnTunnel())).To(BeNil())

	// Test Update Firewall Policy - TBD

	// Test Deleting IPSec VPN Tunnel
	Expect(sSP.ProcessDeletedIPSecVpnTunnelConfig(getConfigIPSecVpnTunnel())).To(BeNil())
}

// Service Route Config Test
func getConfigServiceRouteForBase() *sasemodel.ServiceRoute {

	// Service Route
	routeCfg := &sasemodel.ServiceRoute{
		ServiceInstanceName: "0/local/routing",
		DestinationNetwork:  "11.11.11.11/24",
		GatewayAddress:      "1.1.1.1",
		VrfName:             "default",
		EgressInterface:     "memif1",
	}

	return routeCfg
}

// Service Route Config Test
func getConfigServiceRouteForNonBase() *sasemodel.ServiceRoute {

	// Service Route
	routeCfg := &sasemodel.ServiceRoute{
		ServiceInstanceName: "1/sjc/routing",
		RouteNetworkScope:   "global",
		DestinationNetwork:  "12.12.12.12/24",
		GatewayAddress:      "1.1.1.1",
		VrfName:             "customIf",
		EgressInterface:     "memif1",
	}

	return routeCfg
}

func TestProcessorServiceRoute(t *testing.T) {

	RegisterTestingT(t)
	sSP := initTest()
	Expect(sSP).NotTo(BeNil())

	// Base VPP Routing Config

	// Service Route Config Test
	Expect(sSP.ProcessNewServiceRouteConfig(getConfigServiceRouteForBase())).To(BeNil())

	// Test Deleting Service Route
	Expect(sSP.ProcessDeletedServiceRouteConfig(getConfigServiceRouteForBase())).To(BeNil())

	// Non Base VPP Routing Config
	// Add New Pod with ipsec vpn service
	Expect(sSP.ProcessNewPod(getNewPod())).To(BeNil())

	// Service Route Config Test
	Expect(sSP.ProcessNewServiceRouteConfig(getConfigServiceRouteForNonBase())).To(BeNil())

	// Test Deleting Service Route
	Expect(sSP.ProcessDeletedServiceRouteConfig(getConfigServiceRouteForNonBase())).To(BeNil())

}
