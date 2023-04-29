package networkscanner

type ApplicationDiscoveryListItem struct {
	Discovery  ApplicationLayerDiscovery
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
		Reqirement: string(TCP),
	},
	{
		Discovery:  &RedisDiscovery{},
		Reqirement: string(TCP),
	},
}
