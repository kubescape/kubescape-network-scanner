package applicationlayerdiscovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type EtcdDiscoveryResult struct {
	isDetected      bool
	properties      map[string]interface{}
	isAuthenticated bool
}

func (r *EtcdDiscoveryResult) Protocol() string {
	return "etcd"
}

func (r *EtcdDiscoveryResult) GetIsDetected() bool {
	return r.isDetected
}

func (r *EtcdDiscoveryResult) GetProperties() map[string]interface{} {
	return r.properties
}

func (r *EtcdDiscoveryResult) GetIsAuthRequired() bool {
	return r.isAuthenticated
}

type EtcdDiscovery struct {
}

func (d *EtcdDiscovery) Protocol() string {
	return "etcd"
}

func (d *EtcdDiscovery) Discover(sessionHandler servicediscovery.ISessionHandler, presentationLayerDiscoveryResult servicediscovery.IPresentationDiscoveryResult) (servicediscovery.IApplicationDiscoveryResult, error) {
	endpoints := []string{fmt.Sprintf("%s:%d", sessionHandler.GetHost(), sessionHandler.GetPort())}
	config := clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: 3 * time.Second,
	}

	client, err := clientv3.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to etcd server: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err = client.Get(ctx, "/")
	cancel()
	if err != nil {
		if strings.Contains(err.Error(), "etcdserver: request timed out") {
			return nil, fmt.Errorf("etcd request timed out")
		}
		return nil, fmt.Errorf("failed to discover etcd: %v", err)
	}

	result := &EtcdDiscoveryResult{
		isDetected:      true,
		isAuthenticated: true,
		properties:      nil, // Set properties to nil as it's not used in this case
	}

	return result, nil
}
