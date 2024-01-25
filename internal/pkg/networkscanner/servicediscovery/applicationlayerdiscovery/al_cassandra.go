package applicationlayerdiscovery

import (
	"time"

	"github.com/gocql/gocql"
	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery"
)

const (
	// Default Username
	Username = "cassandra"
	// Default Password
	Password = "cassandra"
)

type CassandraDiscoveryResult struct {
	IsDetected      bool
	properties      map[string]interface{}
	isAuthenticated bool
}

type CassandraDiscovery struct{}

func (r *CassandraDiscoveryResult) Protocol() string {
	return "cassandra"
}

func (r *CassandraDiscoveryResult) GetIsAuthRequired() bool {
	return false
}

func (r *CassandraDiscoveryResult) GetIsDetected() bool {
	return r.IsDetected
}

func (r *CassandraDiscoveryResult) GetProperties() map[string]interface{} {
	return r.properties
}

func (d *CassandraDiscovery) Protocol() string {
	return "cassandra"
}

func (d *CassandraDiscovery) Discover(sessionHandler servicediscovery.ISessionHandler, presentationLayerDiscoveryResult servicediscovery.IPresentationDiscoveryResult) (servicediscovery.IApplicationDiscoveryResult, error) {
	// Set the Cassandra cluster hosts
	clusterHosts := []string{sessionHandler.GetHost()}
	// Create a cluster configuration
	cluster := gocql.NewCluster(clusterHosts...)
	cluster.Port = sessionHandler.GetPort()

	// Set authentication credentials if provided
	cluster.Authenticator = gocql.PasswordAuthenticator{
		Username: Username,
		Password: Password,
	}
	cluster.Timeout = time.Second * 3

	// Create a session
	session, err := cluster.CreateSession()
	if err != nil {
		return &CassandraDiscoveryResult{
			IsDetected:      false,
			isAuthenticated: true,
			properties:      nil, // Set properties to nil as it's not used in this case
		}, nil
	}
	defer session.Close()

	return &CassandraDiscoveryResult{
		IsDetected:      true,
		isAuthenticated: false,
		properties:      nil, // Set properties to nil as it's not used in this case
	}, nil
}
