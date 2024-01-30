package applicationlayerdiscovery

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/kubescape/kubescape-network-scanner/pkg/networkscanner/servicediscovery"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc/grpclog"
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
		return &EtcdDiscoveryResult{
			isDetected:      false,
			isAuthenticated: true,
			properties:      nil,
		}, err
	}
	defer client.Close()
	grpclog.SetLoggerV2(grpclog.NewLoggerV2(io.Discard, io.Discard, io.Discard))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err = client.Get(ctx, "/")
	cancel()
	if err != nil {
		return &EtcdDiscoveryResult{
			isDetected:      true,
			isAuthenticated: true,
			properties:      nil,
		}, nil
	}

	result := &EtcdDiscoveryResult{
		isDetected:      true,
		isAuthenticated: false,
		properties:      nil,
	}

	return result, nil
}
