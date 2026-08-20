package applicationlayerdiscovery

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

type kubeApiTestTarget struct {
	host string
	port int
}

func (f *kubeApiTestTarget) Connect() error              { return nil }
func (f *kubeApiTestTarget) Destory() error              { return nil }
func (f *kubeApiTestTarget) Write(b []byte) (int, error) { return len(b), nil }
func (f *kubeApiTestTarget) Read(b []byte) (int, error)  { return 0, nil }
func (f *kubeApiTestTarget) GetHost() string             { return f.host }
func (f *kubeApiTestTarget) GetPort() int                { return f.port }

// A real, unauthenticated Kubernetes API server reports its kind in the
// JSON body of a GET /api response, not in an HTTP header - no server
// actually sends a "kind" header, so checking resp.Header.Get("kind")
// never matches anything real.
func TestKubeApiServerDiscovery_DetectsFromBodyNotHeader(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"kind":"APIVersions","versions":["v1"]}`))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	target := &kubeApiTestTarget{host: u.Hostname(), port: port}

	d := &KubeApiServerDiscovery{}
	result, err := d.Discover(target, nil)
	if err != nil {
		t.Fatalf("Discover returned an error: %v", err)
	}
	if !result.GetIsDetected() {
		t.Errorf("expected a Kubernetes API server response to be detected, got IsDetected=false")
	}
	if result.GetIsAuthRequired() {
		t.Errorf("expected an unauthenticated 200 response to report auth not required")
	}
}
