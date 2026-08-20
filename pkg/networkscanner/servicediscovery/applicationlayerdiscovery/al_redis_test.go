package applicationlayerdiscovery

import (
	"runtime"
	"testing"
	"time"
)

type redisTestTarget struct {
	host string
	port int
}

func (f *redisTestTarget) Connect() error              { return nil }
func (f *redisTestTarget) Destory() error              { return nil }
func (f *redisTestTarget) Write(b []byte) (int, error) { return len(b), nil }
func (f *redisTestTarget) Read(b []byte) (int, error)  { return 0, nil }
func (f *redisTestTarget) GetHost() string             { return f.host }
func (f *redisTestTarget) GetPort() int                { return f.port }

// redis.NewClient starts a background connection-pool goroutine per client
// that only stops on Close, whether or not anything ever actually connects.
func TestRedisDiscovery_ClosesConnectionPool(t *testing.T) {
	d := &RedisDiscovery{}
	target := &redisTestTarget{host: "127.0.0.1", port: 1} // port 1 is reliably closed

	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	before := runtime.NumGoroutine()

	const calls = 20
	for i := 0; i < calls; i++ {
		_, _ = d.Discover(target, nil)
	}

	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	after := runtime.NumGoroutine()

	if delta := after - before; delta >= calls {
		t.Errorf("Discover leaked a goroutine per call: %d goroutines before, %d after %d calls (delta %d)", before, after, calls, delta)
	}
}
