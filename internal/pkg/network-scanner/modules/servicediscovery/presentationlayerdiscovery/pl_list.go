package networkscanner

type PresentationLayerDiscoveryListItem struct {
	Discovery  PresentationLayerDiscovery
	Reqirement string
}

var PresentationDiscoveryList = []PresentationLayerDiscoveryListItem{
	{
		Discovery:  &HttpDiscovery{},
		Reqirement: string(TCP),
	},
}
