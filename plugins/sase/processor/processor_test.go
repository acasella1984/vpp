package processor_test

import (
	"testing"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/sase/common"
	"github.com/contiv/vpp/plugins/sase/processor"
	firewallservice "github.com/contiv/vpp/plugins/sase/renderer/firewall"
	ipsecservice "github.com/contiv/vpp/plugins/sase/renderer/ipsec"
	natservice "github.com/contiv/vpp/plugins/sase/renderer/nat"
	routeservice "github.com/contiv/vpp/plugins/sase/renderer/route"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
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
			Log: sSP.Log,
		},
	}

	// Firewall
	fireR := &firewallservice.Renderer{
		Deps: firewallservice.Deps{
			Log: sSP.Log,
		},
	}

	// ipsec
	ipsecR := &ipsecservice.Renderer{
		Deps: ipsecservice.Deps{
			Log: sSP.Log,
		},
	}

	// routing
	routeR := &routeservice.Renderer{
		Deps: routeservice.Deps{
			Log: sSP.Log,
		},
	}

	// Register renderer.
	sSP.RegisterRenderer(common.ServiceTypeNAT, natR)
	sSP.RegisterRenderer(common.ServiceTypeFirewall, fireR)
	sSP.RegisterRenderer(common.ServiceTypeIPSecVpn, ipsecR)
	sSP.RegisterRenderer(common.ServiceTypeRouting, routeR)

	return sSP

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
	pod.Annotations["contivpp.io/sase-service"] = "1/sjc/ipsecvpn, 1/sjc/firewall, 1/sjc/nat"
	// microservice label
	pod.Annotations["contivpp.io/microservice-label"] = "vpp-cnf-all"

	//label
	pod.Labels = make(map[string]string)
	pod.Labels["app"] = "vpp-cnf-all"

	return pod
}

func TestProcessorInit(t *testing.T) {
	RegisterTestingT(t)
	sSP := initTest()
	Expect(sSP).NotTo(BeNil())
}

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
