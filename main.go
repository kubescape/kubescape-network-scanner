package main

import (
	"context"
	"fmt"
	_ "net/http/pprof"
	"sync"
	"time"

	"github.com/kubescape/kubescape-network-scanner/cmd"
)

type address struct {
	name string
	ip   string
	port int
}

func main() {
	addresses := []address{{"dashboard-metrics-scraper", "10.109.106.102", 8000}, {"kubernetes-dashboard", "10.99.75.144", 80}, {"kubernetes", "10.96.0.1", 443}, {"kube-dns", "10.96.0.10", 53}, {"kube-dns", "10.96.0.10", 9153}, {"dashboard-metrics-scraper", "10.109.106.102", 8000}, {"kubernetes-dashboard", "10.99.75.144", 80},
		{"kubescape", "10.110.83.73", 8080}, {"kubevuln", "10.99.107.168", 8080}, {"node-agent", "10.103.188.164", 8080}, {"operator", "10.105.88.114", 4002}, {"storage", "10.104.25.88", 443}}

	fmt.Println(addresses)

	fmt.Println("statrting scan")
	var wg sync.WaitGroup
	for _, addr := range addresses {
		wg.Add(1)
		go func(addr address) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			ch := make(chan bool, 1)

			go func() {
				fmt.Printf("start scanning : %s %s:%v \n", addr.name, addr.ip, addr.port)
				result, err := cmd.ScanTargets(context.Background(), addr.ip, addr.port)
				if err == nil {
					fmt.Println(addr.name, " | ", result.ApplicationLayer, " | ", result.IsAuthenticated)
				} else {

					fmt.Println(err)
				}
				ch <- true
			}()

			select {
			case <-ctx.Done():
				fmt.Printf("Got Timeout - service: %s | address: %s:%v\n ", addr.name, addr.ip, addr.port)
				return
			case <-ch:
				return
			}

		}(addr)

	}
	wg.Wait()
	fmt.Println("finish")

}
