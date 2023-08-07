package applicationlayerdiscovery

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery"
)

type MongoDBDiscoveryResult struct {
	isDetected      bool
	properties      map[string]interface{}
	isAuthenticated bool
}

func (r *MongoDBDiscoveryResult) Protocol() string {
	return "mongodb"
}

func (r *MongoDBDiscoveryResult) GetIsDetected() bool {
	return r.isDetected
}

func (r *MongoDBDiscoveryResult) GetProperties() map[string]interface{} {
	return r.properties
}

func (r *MongoDBDiscoveryResult) GetIsAuthRequired() bool {
	return r.isAuthenticated
}

type MongoDBDiscovery struct {
}

func (d *MongoDBDiscovery) Protocol() string {
	return "mongodb"
}

func (d *MongoDBDiscovery) Discover(sessionHandler servicediscovery.ISessionHandler, presentationLayerDiscoveryResult servicediscovery.IPresentationDiscoveryResult) (servicediscovery.IApplicationDiscoveryResult, error) {
	clientOptions := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s:%d", sessionHandler.GetHost(), sessionHandler.GetPort()))
	ctx := context.Background()
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		fmt.Printf("failed to connect to MongoDB server: %v\n", err)
		return nil, fmt.Errorf("failed to connect to MongoDB server: %v", err)
	}

	// Here: we know it is MongoDB, but we don't know if it is authenticated or not
	result := &MongoDBDiscoveryResult{
		isDetected:      true,
		isAuthenticated: true,
		properties:      nil, // Set properties to nil as it's not used in this case
	}

	// Test the connection
	err = client.Ping(ctx, nil)
	if err != nil {
		fmt.Printf("failed to ping MongoDB server: %v\n", err)
	}

	// Get MongoDB server version
	serverStatusCmd := bson.D{{"serverStatus", 1}, {"recordStats", 0}}
	serverStatusResult := client.Database("admin").RunCommand(ctx, serverStatusCmd)
	if serverStatusResult.Err() == nil {
		var resultDoc bson.D
		err = serverStatusResult.Decode(&resultDoc)
		if err == nil {
			version, _ := resultDoc.Map()["version"].(string)
			host, _ := resultDoc.Map()["host"].(string)
			result.isAuthenticated = false
			result.properties = map[string]interface{}{
				"host":    host,
				"version": version,
			}
		} else {
			fmt.Printf("failed to decode server status result: %v\n", err)
		}
	} else {
		fmt.Printf("failed to retrieve server status: %v\n", serverStatusResult.Err())
	}

	client.Disconnect(ctx)
	return result, nil
}
