// podresources-list queries only the kubelet PodResources v1 List endpoint on
// the local Linux node and emits the one explicitly selected GPU allocation.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pr "k8s.io/kubelet/pkg/apis/podresources/v1"
)

const resourceName = "nvidia.com/gpu"

type allocation struct {
	Namespace string   `json:"namespace"`
	Pod       string   `json:"pod"`
	Container string   `json:"container"`
	Resource  string   `json:"resource_name"`
	DeviceIDs []string `json:"device_ids"`
}

type source struct {
	Schema           string       `json:"schema"`
	CapturedAtUTC    string       `json:"captured_at_utc"`
	APIVersion       string       `json:"api_version"`
	API              string       `json:"api"`
	KubeletModule    string       `json:"kubelet_module"`
	HostOS           string       `json:"host_os"`
	HostArchitecture string       `json:"host_architecture"`
	Hostname         string       `json:"hostname"`
	NodeName         string       `json:"node_name"`
	SocketPath       string       `json:"socket_path"`
	Entries          []allocation `json:"entries"`
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

func main() {
	socket := flag.String("socket", "/var/lib/kubelet/pod-resources/kubelet.sock", "local kubelet PodResources Unix socket")
	node := flag.String("node-name", "", "exact Kubernetes node name observed from the workload Pod")
	namespace := flag.String("namespace", "saf-gpu-a100", "exact workload namespace")
	podName := flag.String("pod", "a100-vector-witness", "exact workload Pod name")
	container := flag.String("container", "vector", "exact workload container name")
	expectedDevices := flag.Int("expected-device-count", 1, "exact number of requested NVIDIA GPU devices")
	timeout := flag.Duration("timeout", 5*time.Second, "bounded local gRPC call timeout")
	flag.Parse()

	if flag.NArg() != 0 {
		fail("unexpected positional arguments")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		fail("requires linux/amd64 host; got %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	fixtureResources := map[string]string{
		"a100-vector-witness": resourceName,
		"a100-mig-a":          "nvidia.com/mig-1g.5gb",
		"a100-mig-b":          "nvidia.com/mig-1g.5gb",
	}
	selectedResource := fixtureResources[*podName]
	if *node == "" || *namespace != "saf-gpu-a100" || selectedResource == "" || *container != "vector" {
		fail("exact fixture node and workload identity are required")
	}
	if *expectedDevices != 1 || *timeout <= 0 || *timeout > 10*time.Second {
		fail("device count must be one and timeout must be within 1..10 seconds")
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		fail("could not read local hostname")
	}
	if host != *node {
		fail("local hostname does not match the selected Kubernetes node name")
	}
	if _, err := os.Stat(*socket); err != nil {
		fail("local PodResources socket unavailable: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", *socket)
	}
	conn, err := grpc.DialContext(ctx, "passthrough:///kubelet-podresources",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock())
	if err != nil {
		fail("could not connect to local PodResources socket: %v", err)
	}
	defer conn.Close()

	response, err := pr.NewPodResourcesListerClient(conn).List(ctx, &pr.ListPodResourcesRequest{})
	if err != nil {
		fail("PodResources v1 List failed: %v", err)
	}
	var matches []allocation
	for _, p := range response.GetPodResources() {
		if p.GetNamespace() != *namespace || p.GetName() != *podName {
			continue
		}
		for _, c := range p.GetContainers() {
			if c.GetName() != *container {
				continue
			}
			var deviceSets [][]string
			for _, d := range c.GetDevices() {
				if d.GetResourceName() == selectedResource {
					deviceSets = append(deviceSets, append([]string(nil), d.GetDeviceIds()...))
				}
			}
			if len(deviceSets) != 1 {
				fail("exact workload container must have exactly one %s allocation record", selectedResource)
			}
			ids := deviceSets[0]
			sort.Strings(ids)
			if len(ids) != *expectedDevices || ids[0] == "" {
				fail("PodResources device count does not match expected allocation")
			}
			seen := map[string]bool{}
			for _, id := range ids {
				if seen[id] {
					fail("PodResources returned duplicate device ID")
				}
				seen[id] = true
			}
			matches = append(matches, allocation{Namespace: *namespace, Pod: *podName,
				Container: *container, Resource: selectedResource, DeviceIDs: ids})
		}
	}
	if len(matches) != 1 {
		fail("expected one exact workload Pod/container allocation; got %d", len(matches))
	}

	out := source{
		Schema: "saf-k8s-podresources-source-v1", CapturedAtUTC: time.Now().UTC().Format(time.RFC3339Nano),
		APIVersion: "v1", API: "/v1.PodResourcesLister/List", KubeletModule: "k8s.io/kubelet@v0.36.6",
		HostOS: runtime.GOOS, HostArchitecture: runtime.GOARCH, Hostname: host,
		NodeName: *node, SocketPath: *socket, Entries: matches,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		fail("could not encode bounded capture")
	}
}
