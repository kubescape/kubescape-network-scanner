package applicationlayerdiscovery

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/kubescape/kubescape-network-scanner/pkg/networkscanner/servicediscovery"
)

type RedisDiscoveryResult struct {
	isDetected      bool
	properties      map[string]interface{}
	isAuthenticated bool
}

func (r *RedisDiscoveryResult) Protocol() string {
	return "redis"
}

func (r *RedisDiscoveryResult) GetIsDetected() bool {
	return r.isDetected
}

func (r *RedisDiscoveryResult) GetProperties() map[string]interface{} {
	return r.properties
}

func (r *RedisDiscoveryResult) GetIsAuthRequired() bool {
	return r.isAuthenticated
}

type RedisDiscovery struct {
}

func (d *RedisDiscovery) Protocol() string {
	return "redis"
}

func (d *RedisDiscovery) Discover(sessionHandler servicediscovery.ISessionHandler, presentationLayerDiscoveryResult servicediscovery.IPresentationDiscoveryResult) (servicediscovery.IApplicationDiscoveryResult, error) {

	redisClient := redis.NewClient(&redis.Options{
		Addr:        fmt.Sprintf("%s:%d", sessionHandler.GetHost(), sessionHandler.GetPort()),
		Password:    "", // No password for now, modify as needed
		DB:          0,  // Use default DB
		DialTimeout: 500 * time.Millisecond,
		MaxRetries:  1,
	})

	pong, err := redisClient.Ping(context.TODO()).Result()
	if err != nil {
		// Even if there is an error, we can still detect Redis
		result := &RedisDiscoveryResult{
			isDetected:      false,
			isAuthenticated: true,
			properties:      nil, // Set properties to nil as it's not used in this case
		}
		return result, nil
	}

	if pong != "PONG" {
		return &RedisDiscoveryResult{
			isDetected:      true,
			isAuthenticated: true,
			properties:      nil, // Set properties to nil as it's not used in this case
		}, nil
	}

	// Redis connection successful, populate properties if needed
	result := &RedisDiscoveryResult{
		isDetected:      true,
		isAuthenticated: false,
		properties:      nil, // Set properties to nil as it's not used in this case
	}

	return result, nil
}
