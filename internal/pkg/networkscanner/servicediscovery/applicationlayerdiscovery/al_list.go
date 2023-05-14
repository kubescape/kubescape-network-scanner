package applicationlayerdiscovery

import (
	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery"
)

type ApplicationDiscoveryListItem struct {
	Discovery  servicediscovery.ApplicationLayerDiscovery
	Reqirement string
}

var ApplicationDiscoveryList = []ApplicationDiscoveryListItem{
	//{
	//Discovery:  &KubeletDiscovery{},
	//Reqirement: string(HTTP),
	//},
	//{
	//	Discovery:  &KubeApiServerDiscovery{},
	//	Reqirement: string(HTTP),
	//},
	{
		Discovery:  &MysqlDiscovery{},
		Reqirement: string(servicediscovery.TCP),
	},
	{
		Discovery:  &PostgresDiscovery{},
		Reqirement: string(servicediscovery.TCP),
	},
}
