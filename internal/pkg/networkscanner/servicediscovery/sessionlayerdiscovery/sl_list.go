package sessionlayerdiscovery

import (
	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery"
)

type SessionLayerDiscoveryListItem struct {
	Discovery  servicediscovery.SessionLayerProtocolDiscovery
	Reqirement string
}

var SessionDiscoveryList = []SessionLayerDiscoveryListItem{
	{
		Discovery:  &TlsSessionDiscovery{},
		Reqirement: string(servicediscovery.TCP),
	},
}
