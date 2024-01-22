package applicationlayerdiscovery

import (
	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery"
)

type ApplicationDiscoveryListItem struct {
	Discovery  servicediscovery.ApplicationLayerDiscovery
	Reqirement string
}

var ApplicationDiscoveryList = []ApplicationDiscoveryListItem{
	{
		Discovery:  &KubeApiServerDiscovery{},
		Reqirement: string(servicediscovery.TCP),
	},
	{
		Discovery:  &ElasticsearchDiscovery{},
		Reqirement: string(servicediscovery.TCP),
	},
	{
		Discovery:  &MysqlDiscovery{},
		Reqirement: string(servicediscovery.TCP),
	},
	{
		Discovery:  &PostgresDiscovery{},
		Reqirement: string(servicediscovery.TCP),
	},
	{
		Discovery:  &RedisDiscovery{},
		Reqirement: string(servicediscovery.TCP),
	},
	{
		Discovery:  &EtcdDiscovery{},
		Reqirement: string(servicediscovery.TCP),
	},
	{
		Discovery:  &MongoDBDiscovery{},
		Reqirement: string(servicediscovery.TCP),
	},
	{
		Discovery:  &RabbitMQDiscovery{},
		Reqirement: string(servicediscovery.TCP),
	},
	{
		Discovery:  &KafkaDiscovery{},
		Reqirement: string(servicediscovery.TCP),
	},
	{
		Discovery:  &CassandraDiscovery{},
		Reqirement: string(servicediscovery.TCP),
	},
}
