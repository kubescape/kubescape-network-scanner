package presentationlayerdiscovery

import (
	"github.com/kubescape/kubescape-network-scanner/pkg/networkscanner/servicediscovery"
)

type PresentationLayerDiscoveryListItem struct {
	Discovery  servicediscovery.PresentationLayerDiscovery
	Reqirement string
}

var PresentationDiscoveryList = []PresentationLayerDiscoveryListItem{
	{
		Discovery:  &HttpDiscovery{},
		Reqirement: string(servicediscovery.TCP),
	},
}
