package applicationlayerdiscovery

import (
	"runtime"
	"testing"
	"time"

	"github.com/kubescape/kubescape-network-scanner/pkg/networkscanner/servicediscovery"
)

type fakeSessionHandler struct {
	host string
	port int
}

func (f *fakeSessionHandler) Connect() error              { return nil }
func (f *fakeSessionHandler) Destory() error              { return nil }
func (f *fakeSessionHandler) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeSessionHandler) Read(b []byte) (int, error)  { return 0, nil }
func (f *fakeSessionHandler) GetHost() string             { return f.host }
func (f *fakeSessionHandler) GetPort() int                { return f.port }

var _ servicediscovery.ISessionHandler = (*fakeSessionHandler)(nil)

// Discover creates a new *sql.DB per call. sql.Open starts a background
// connectionOpener goroutine that only stops when Close is called, so a
// missing Close leaks one goroutine per call regardless of whether the
// target actually speaks MySQL.
func TestMysqlDiscovery_ClosesConnectionPool(t *testing.T) {
	d := &MysqlDiscovery{}
	target := &fakeSessionHandler{host: "127.0.0.1", port: 1} // port 1 is reliably closed

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
