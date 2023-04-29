package networkscanner

type SessionLayerDiscoveryListItem struct {
	Discovery  SessionLayerProtocolDiscovery
	Reqirement string
}

var SessionDiscoveryList = []SessionLayerDiscoveryListItem{
	{
		Discovery:  &TlsSessionDiscovery{},
		Reqirement: string(TCP),
	},
}
