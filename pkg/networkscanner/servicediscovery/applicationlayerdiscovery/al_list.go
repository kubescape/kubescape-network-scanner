package applicationlayerdiscovery

import (
	"github.com/kubescape/kubescape-network-scanner/pkg/networkscanner/servicediscovery"
)

type ApplicationDiscoveryListItem struct {
	Discovery   servicediscovery.ApplicationLayerDiscovery
	Reqirement  string
	CommonPorts []int
}

var ApplicationDiscoveryList = []ApplicationDiscoveryListItem{
	{
		Discovery:  &KubeApiServerDiscovery{},
		Reqirement: string(servicediscovery.TCP),
		CommonPorts: []int{
			6443,
		},
	},
	// {
	// 	Discovery:  &ElasticsearchDiscovery{},
	// 	Reqirement: string(servicediscovery.TCP),
	// 	CommonPorts: []int{
	// 		9200,
	// 	},
	// },
	{
		Discovery:  &MysqlDiscovery{},
		Reqirement: string(servicediscovery.TCP),
		CommonPorts: []int{
			3306,
		},
	},
	{
		Discovery:  &PostgresDiscovery{},
		Reqirement: string(servicediscovery.TCP),
		CommonPorts: []int{
			5432,
		},
	},
	{
		Discovery:  &RedisDiscovery{},
		Reqirement: string(servicediscovery.TCP),
		CommonPorts: []int{
			6379,
		},
	},
	{
		Discovery:  &EtcdDiscovery{},
		Reqirement: string(servicediscovery.TCP),
		CommonPorts: []int{
			2379,
		},
	},
	{
		Discovery:  &MongoDBDiscovery{},
		Reqirement: string(servicediscovery.TCP),
		CommonPorts: []int{
			27017,
		},
	},
	{
		Discovery:  &RabbitMQDiscovery{},
		Reqirement: string(servicediscovery.TCP),
		CommonPorts: []int{
			5672,
		},
	},
	{
		Discovery:  &KafkaDiscovery{},
		Reqirement: string(servicediscovery.TCP),
		CommonPorts: []int{
			9092,
		},
	},
	{
		Discovery:  &CassandraDiscovery{},
		Reqirement: string(servicediscovery.TCP),
		CommonPorts: []int{
			9042,
		},
	},
}
