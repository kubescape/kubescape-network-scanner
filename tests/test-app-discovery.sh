#!/bin/bash
# Usage: test-app-discovery.sh <application-name>
# set -x

# Clean-up and exit function
function cleanupandexit() {
    # Print error message (first argument)
    testprint "$1 - $2" "red"
    # Delete the namespace
    kubectl delete namespace $namespace
    exit 1
}

# Test printer function
function testprint() {
    # Check if it is an interactive shell
    if [ -t 1 ]; then
        # Second argument is the color
        if [ "$2" == "red" ]; then
            # Print in red
            echo -e "\e[31m$1\e[0m"
        elif [ "$2" == "green" ]; then
            # Print in green
            echo -e "\e[32m$1\e[0m"
        else
            # Print in white
            echo "$1"
        fi
    else
        # Print in white
        # if red, put an error prefix, if green, put a success prefix
        if [ "$2" == "red" ]; then
            echo "[ERROR] $1"
        elif [ "$2" == "green" ]; then
            echo "[SUCCESS] $1"
        else
            echo "$1"
        fi
    fi
}

# Check if kubectl is available
if ! command -v kubectl &> /dev/null
then
    testprint "kubectl could not be found" "red"
    exit 1
fi

# Check if jq is available
if ! command -v jq &> /dev/null
then
    testprint "jq could not be found" "red"
    exit 1
fi

# Check if kubernetes is running
if ! kubectl cluster-info &> /dev/null
then
    testprint "Kubernetes is not running" "red"
    exit 1
fi

# Read application name from command line
if [ $# -eq 0 ]; then
    testprint "No application name provided" "red"
    exit 1
fi

application_name=$1

testprint "[INFO] Testing application $application_name" "white"

# Check if application exists
if [ ! -d "apps/$application_name" ]; then
    testprint "Application $application_name does not exist" "red"
    exit 1
fi

# Check if app.yaml exists
if [ ! -f "apps/$application_name/app.yaml" ] && [ ! -f "apps/$application_name/config.yaml" ]; then
    testprint "app.yaml or config.yaml does not exist" "red"
    exit 1
fi

APP_YAML=""
# Check if app.yaml exists
if [ -f "apps/$application_name/app.yaml" ]; then
    APP_YAML="apps/$application_name/app.yaml"
fi

CONFIG_YAML=""
# Check if config.yaml exists
if [ -f "apps/$application_name/config.yaml" ]; then
    CONFIG_YAML="apps/$application_name/config.yaml"
fi

# Check if expected output json file exists
if [ ! -f "apps/$application_name/expected-output.json" ]; then
    testprint "expected-output.json does not exist" "red"
    exit 1
fi

# Create a random namespace
random_name=$(openssl rand -hex 4)
namespace="test-$random_name"

# Create a namespace
kubectl create namespace $namespace || exit 1

# Print out the namespace and the service account
kubectl get serviceaccount -n $namespace


# If app.yaml exists, apply it
if [ ! -z "$APP_YAML" ]; then
    # Apply app.yaml
    kubectl apply -f $APP_YAML -n $namespace || cleanupandexit $application_name "failed to apply app.yaml"
    # Wait for the application to be ready
    kubectl wait --for=condition=ready pod -l app=$application_name -n $namespace
    # Check result
    if [ $? -ne 0 ]; then
        kubectl describe pods -n $namespace -l app=$application_name
        cleanupandexit $application_name "application is not ready after 5 minutes"
    fi
fi

# If config.yaml exists, get service name and port from it
if [ ! -z "$CONFIG_YAML" ]; then
    # Use sed to extract serviceName and servicePort from config.yaml
    service_name=$(cat $CONFIG_YAML | sed -n 's/.*serviceName: *//p')
    service_port=$(cat $CONFIG_YAML | sed -n 's/.*servicePort: *//p')
else
    # Get the application's service name
    service_name=$(kubectl get service -l app=$application_name -n $namespace -o jsonpath='{.items[0].metadata.name}')

    # Get the application's service port
    service_port=$(kubectl get service -l app=$application_name -n $namespace -o jsonpath='{.items[0].spec.ports[0].port}')
fi


# Make sure that service name and port are not empty
if [ -z "$service_name" ] || [ -z "$service_port" ]; then
    cleanupandexit $application_name "service name or port is empty"
fi

# Create a test pod in the same namespace
# retry 5 times with 1 second sleep
success=false
for i in {1..5}; do
    kubectl -n $namespace run bash-pod --image=bash:latest --restart=Never --command -- sleep infinity
    if [ $? -eq 0 ]; then
        success=true
        break
    fi
    sleep 1
done
$success || cleanupandexit $application_name "failed to create test pod"

# Wait for the pod to be ready
kubectl wait --for=condition=ready pod -l run=bash-pod -n $namespace || cleanupandexit $application_name "test pod is not ready after 5 minutes"

# Copy the kubescape-network-scanner binary to the pod
kubectl cp ../kubescape-network-scanner bash-pod:/usr/local/bin/kubescape-network-scanner -n $namespace || cleanupandexit $application_name "failed to copy kubescape-network-scanner to the pod"

testprint "Service name: $service_name" "white"
kubectl -n $namespace get service -o wide

# Run the kubescape-network-scanner binary in the pod
kubectl exec bash-pod -n $namespace -- kubescape-network-scanner scan --tcp $service_name $service_port --json --output /tmp/output.json || cleanupandexit $application_name "failed to run kubescape-network-scanner in the pod"

# Get the output json file from the pod
kubectl cp bash-pod:/tmp/output.json /tmp/$random_name-output.json -n $namespace 2>&1 | tee /tmp/$random_name-log.txt || cleanupandexit $application_name "failed to copy output.json from the pod"

# Compare the output json file with the expected output json file (ignore whitespace)
#jq -S . /tmp/$random_name-output.json > /tmp/$random_name-output.json.tmp && mv /tmp/$random_name-output.json.tmp /tmp/$random_name-output.json
#jq -S . apps/$application_name/expected-output.json > /tmp/$random_name-expected-output.json
# Compare the output json file with the expected output json file (ignore whitespace and "properties" field)
jq --sort-keys -S 'map(.properties |= {})' /tmp/$random_name-output.json > /tmp/$random_name-output.json.tmp \
  && mv /tmp/$random_name-output.json.tmp /tmp/$random_name-output.json
jq --sort-keys -S 'map(.properties |= {})' apps/$application_name/expected-output.json > /tmp/$random_name-expected-output.json
diff -w /tmp/$random_name-output.json /tmp/$random_name-expected-output.json > /tmp/$random_name-diff.txt
result=$?

# If successful, result will be 0 and print out success message, if not, print out failure message
if [ $result -eq 0 ]; then
    testprint "Test $application_name passed successfully" "green"
else
    testprint "Test failed" "red"
    testprint "Diff:" "red"
    cat /tmp/$random_name-diff.txt
    # Print the diff to stderr
    echo "----------------------------------------" >&2
    cat /tmp/$random_name-log.txt >&2
    echo "----------------------------------------" >&2
    echo "Diff:" >&2
    cat /tmp/$random_name-diff.txt >&2
    echo "----------------------------------------" >&2
fi

# Delete the namespace
kubectl delete namespace $namespace

# Delete temporary files
rm /tmp/$random_name-output.json
rm /tmp/$random_name-expected-output.json
rm /tmp/$random_name-diff.txt

exit $result