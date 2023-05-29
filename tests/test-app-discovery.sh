#!/bin/bash
# Usage: test-app-discovery.sh <application-name>
set -x

# Clean-up and exit function
function cleanupandexit() {
    # Delete the namespace
    kubectl delete namespace $namespace
    exit 1
}

# Check if kubectl is available
if ! command -v kubectl &> /dev/null
then
    echo "kubectl could not be found"
    exit 1
fi

# Check if kubernetes is running
if ! kubectl cluster-info &> /dev/null
then
    echo "Kubernetes is not running"
    exit 1
fi

# Read application name from command line
if [ $# -eq 0 ]; then
    echo "No application name provided"
    exit 1
fi

application_name=$1

# Check if application exists
if [ ! -d "apps/$application_name" ]; then
    echo "Application $application_name does not exist"
    exit 1
fi

# Check if app.yaml exists
if [ ! -f "apps/$application_name/app.yaml" ]; then
    echo "app.yaml does not exist"
    exit 1
fi

# Check if expected output json file exists
if [ ! -f "apps/$application_name/expected-output.json" ]; then
    echo "expected-output.json does not exist"
    exit 1
fi

# Create a random namespace
namespace="test-$(openssl rand -hex 4)"

# Create a namespace
kubectl create namespace $namespace || exit 1

# Apply app.yaml
kubectl apply -f apps/$application_name/app.yaml -n $namespace || cleanupandexit

# Wait for the application to be ready
kubectl wait --for=condition=ready pod -l app=$application_name -n $namespace || cleanupandexit

# Get the application's service name
service_name=$(kubectl get service -l app=$application_name -n $namespace -o jsonpath='{.items[0].metadata.name}')

# Get the application's service port
service_port=$(kubectl get service -l app=$application_name -n $namespace -o jsonpath='{.items[0].spec.ports[0].port}')

# Make sure that service name and port are not empty
if [ -z "$service_name" ] || [ -z "$service_port" ]; then
    echo "Service name or port is empty"
    cleanupandexit
fi

# Create a test pod in the same namespace
kubectl -n $namespace run bash-pod --image=bash:latest --restart=Never --command -- sleep infinity || cleanupandexit

# Wait for the pod to be ready
kubectl wait --for=condition=ready pod -l run=bash-pod -n $namespace || cleanupandexit

# Copy the kubescape-network-scanner binary to the pod
kubectl cp ../kubescape-network-scanner bash-pod:/usr/local/bin/kubescape-network-scanner -n $namespace || cleanupandexit

# Run the kubescape-network-scanner binary in the pod
kubectl exec -it bash-pod -n $namespace -- kubescape-network-scanner Scan --tcp $service_name $service_port --json > /tmp/output.json || cleanupandexit
#kubectl exec -it bash-pod -n $namespace -- kubescape-network-scanner Scan --tcp $service_name $service_port || cleanupandexit
#kubectl exec -it bash-pod -n $namespace -- kubescape-network-scanner Scan --tcp 10.96.0.1 443 || cleanupandexit

# Delete the namespace
kubectl delete namespace $namespace
