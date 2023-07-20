# Kubescape-network-scanner
A network and service discovery package in golang for scanning networks inside kubernetes clusters and finding hidden services. This project is an extension of the Kubescape platform and aims to provide comprehensive network scanning capabilities within Kubernetes environments.

## Key Features
- **No Port Mapping Approach**: Unlike traditional scanners, Kubescape Network Scanner does not rely on port mapping for service discovery. It can uncover hidden services running on different ports, providing a more comprehensive scanning experience.

- **Discover Hidden Services**: Kubescape Network Scanner excels at finding hidden services that may go unnoticed by other scanners, enabling you to identify potential blind spots within your Kubernetes clusters.

- **Authentication Check and Exposed Services Detection**: Kubescape Network Scanner allows you to verify if services are properly authenticated and provides insights into exposed services, helping you mitigate potential risks proactively.

## Installation
```
go get github.com/kubescape/kubescape-network-scanner
go mod tidy
make build
```
## Usage
``` sh
kubescape-network-scanner scan [--tcp|--udp] <host or ip_address or ip_range> [ports...]

optional arguments:
   -h                    show this help message and exit
   --tcp/--udp           scan for tcp/udp ports
   --json                create a json output of result.
   --output              specify the path of result output
```

## Demo

[![asciicast](https://asciinema.org/a/597738.svg)](https://asciinema.org/a/597738)

## How it Works
Kubescape Network Scanner utilizes the OSI model as a framework for understanding and analyzing network communication. The scanning process involves a meticulous layer-by-layer approach, starting from the transport layer all the way up to the application layer. By maintaining seamless connections between layers, Kubescape Network Scanner identifies services running on each layer, providing valuable information for securing your Kubernetes clusters.

![image](https://github.com/0xquark/kubescape-network-scanner/assets/84588720/6c023eb7-2e99-45d1-b7fb-53ddec8ffc81)

Kubescape network scanner is currently able to support following services: 
### Application Layer:
- Etcd
- Kubernetes Api Server
- Postgres
- Redis
- Elastic search

### Presentation Layer
- http
- gRPC ( In Development )

### Session Layer
- tls

### Transport Layer
- tcp
- udp
