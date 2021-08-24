// Copyright 2020 Form3 Financial Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/health/client/connectivity"
	ciliumclient "github.com/cilium/cilium/pkg/client"
	ciliumdefaults "github.com/cilium/cilium/pkg/defaults"
	healthclient "github.com/cilium/cilium/pkg/health/client"
	healthdefaults "github.com/cilium/cilium/pkg/health/defaults"
	"github.com/form3tech-oss/extra-cilium-metrics/version"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const (
	labelProtocol             = "protocol"
	labelSourceCluster        = "source_cluster"
	labelSourceNodeName       = "source_node_name"
	labelTargetCluster        = "target_cluster"
	labelTargetNodeIP         = "target_node_ip"
	labelTargetNodeName       = "target_node_name"
	labelTargetNodeType       = "target_node_type"
	labelType                 = "type"
	labelValueEndpoint        = "endpoint"
	labelValueHTTP            = "http"
	labelValueICMP            = "icmp"
	labelValueLocal           = "local"
	labelValueNode            = "node"
	labelValueRemote          = "remote"
	namespace                 = "cilium_extra"
	nodeNameSeparator         = "/"
	socketsCheckInterval      = 500 * time.Millisecond
	socketsWaitTimeout        = 5 * time.Minute
	subsystemClusterMesh      = "clustermesh"
	subsystemNodeConnectivity = "node_connectivity"
)

type resettableMetric interface {
	Reset()
}

var (
	clusterMeshRemoteClusterEtcdHasQuorum = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "Whether the remote cluster's 'cilium-etcd' cluster has quorum",
		Name:      "remote_cluster_etcd_has_quorum",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSourceCluster,
		labelSourceNodeName,
		labelTargetCluster,
	})
	clusterMeshRemoteClusterEtcdTotalObservedLeases = promauto.NewCounterVec(prometheus.CounterOpts{
		Help:      "The total number of observed lease IDs on the remote cluster's 'cilium-etcd' cluster belonging to the current Cilium agent",
		Name:      "remote_cluster_etcd_total_observed_leases",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSourceCluster,
		labelSourceNodeName,
		labelTargetCluster,
	})
	clusterMeshRemoteClusterEtcdTotalObservedLockLeases = promauto.NewCounterVec(prometheus.CounterOpts{
		Help:      "The total number of observed lock lease IDs on the remote cluster's 'cilium-etcd' cluster belonging to the current Cilium agent",
		Name:      "remote_cluster_etcd_total_observed_lock_leases",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSourceCluster,
		labelSourceNodeName,
		labelTargetCluster,
	})
	clusterMeshRemoteClusterLastFailureTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "The timestamp of the last failure of the remote cluster",
		Name:      "remote_cluster_last_failure_timestamp",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSourceCluster,
		labelSourceNodeName,
		labelTargetCluster,
	})
	clusterMeshRemoteClusterReadinessStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "The readiness status of the remote cluster",
		Name:      "remote_cluster_readiness_status",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSourceCluster,
		labelSourceNodeName,
		labelTargetCluster,
	})
	clusterMeshRemoteClusterTotalFailures = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "The total number of failures related to the remote cluster",
		Name:      "remote_cluster_total_failures",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSourceCluster,
		labelSourceNodeName,
		labelTargetCluster,
	})
	clusterMeshRemoteClusterTotalNodes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "The total number of nodes in the remote cluster",
		Name:      "remote_cluster_total_nodes",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSourceCluster,
		labelSourceNodeName,
		labelTargetCluster,
	})
	clusterMeshTotalGlobalServices = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "The total number of global services in the cluster mesh",
		Name:      "total_global_services",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSourceCluster,
		labelSourceNodeName,
	})
	clusterMeshTotalRemoteClusters = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "The total number of remote clusters meshed with the local cluster",
		Name:      "total_remote_clusters",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSourceCluster,
		labelSourceNodeName,
	})
	nodeConnectivityLatency = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "The last observed latency (in nanoseconds) between the current Cilium agent and other Cilium agents",
		Name:      "latency",
		Namespace: namespace,
		Subsystem: subsystemNodeConnectivity,
	}, []string{
		labelSourceCluster,
		labelSourceNodeName,
		labelTargetCluster,
		labelTargetNodeName,
		labelTargetNodeIP,
		labelTargetNodeType,
		labelType,
		labelProtocol,
	})
	nodeConnectivityStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "The last observed status of the connectivity between the current Cilium agent and other Cilium agents",
		Name:      "status",
		Namespace: namespace,
		Subsystem: subsystemNodeConnectivity,
	}, []string{
		labelSourceCluster,
		labelSourceNodeName,
		labelTargetCluster,
		labelTargetNodeName,
		labelTargetNodeIP,
		labelTargetNodeType,
		labelType,
	})
)

var (
	resettableMetrics = []resettableMetric{
		nodeConnectivityLatency,
		nodeConnectivityStatus,
	}
)

var (
	clusterMeshRemoteClusterEtcdStatusRegex = regexp.MustCompile(`^etcd: \d+/\d+ connected, lease-ID=([0-9a-f]+), lock lease-ID=([0-9a-f]+), has-quorum=true`)
)

var (
	lastEtcdLeaseIDs     = make(map[string]string, 0)
	lastEtcdLockLeaseIDs = make(map[string]string, 0)
)

func boolToInt32(v bool) int32 {
	if v {
		return 1
	}
	return 0
}

func collectMetrics(ciliumClient *ciliumclient.Client, healthClient *healthclient.Client) error {
	// Reset all resettable metrics so that, e.g., nodes that disappear from the cluster(s) are not forever reported as unreachable.
	for _, m := range resettableMetrics {
		m.Reset()
	}

	// Grab information from Cilium's health endpoint.
	h, err := ciliumClient.Daemon.GetHealthz(daemon.NewGetHealthzParamsWithContext(context.TODO()))
	if err != nil {
		return err
	}
	p := strings.Split(h.Payload.Cluster.Self, nodeNameSeparator)
	localClusterName := p[0]
	localNodeName := p[1]
	// Collect metrics about an eventual cluster mesh.
	clusterMeshTotalRemoteClusters.WithLabelValues(localClusterName, h.Payload.Cluster.Self).Set(float64(len(h.Payload.ClusterMesh.Clusters)))
	clusterMeshTotalGlobalServices.WithLabelValues(localClusterName, localNodeName).Set(float64(h.Payload.ClusterMesh.NumGlobalServices))
	for _, c := range h.Payload.ClusterMesh.Clusters {
		if d := clusterMeshRemoteClusterEtcdStatusRegex.FindStringSubmatch(c.Status); len(d) == 0 {
			clusterMeshRemoteClusterEtcdHasQuorum.WithLabelValues(localClusterName, localNodeName, c.Name).Set(0)
		} else {
			clusterMeshRemoteClusterEtcdHasQuorum.WithLabelValues(localClusterName, localNodeName, c.Name).Set(1)
			if d[1] != lastEtcdLeaseIDs[c.Name] {
				lastEtcdLeaseIDs[c.Name] = d[1]
				clusterMeshRemoteClusterEtcdTotalObservedLeases.WithLabelValues(localClusterName, localNodeName, c.Name).Inc()
			}
			if d[2] != lastEtcdLockLeaseIDs[c.Name] {
				lastEtcdLockLeaseIDs[c.Name] = d[2]
				clusterMeshRemoteClusterEtcdTotalObservedLockLeases.WithLabelValues(localClusterName, localNodeName, c.Name).Inc()
			}
		}
		clusterMeshRemoteClusterLastFailureTimestamp.WithLabelValues(localClusterName, localNodeName, c.Name).Set(float64(time.Time(c.LastFailure).UnixNano()))
		clusterMeshRemoteClusterReadinessStatus.WithLabelValues(localClusterName, localNodeName, c.Name).Set(float64(boolToInt32(c.Ready)))
		clusterMeshRemoteClusterTotalFailures.WithLabelValues(localClusterName, localNodeName, c.Name).Set(float64(c.NumFailures))
		clusterMeshRemoteClusterTotalNodes.WithLabelValues(localClusterName, localNodeName, c.Name).Set(float64(c.NumNodes))
	}

	// Collect metrics about node-to-node connectivity.
	c, err := healthClient.Connectivity.GetStatus(connectivity.NewGetStatusParamsWithContext(context.TODO()))
	if err != nil {
		return err
	}
	for _, n := range c.Payload.Nodes {
		p := strings.Split(n.Name, nodeNameSeparator)
		targetClusterName := p[0]
		targetNodeName := p[1]
		nodePathStatus := healthclient.GetHostPrimaryAddress(n)
		nodePathConnectivityStatusType := healthclient.GetPathConnectivityStatusType(nodePathStatus)

		endpointPathStatus := n.Endpoint
		if endpointPathStatus == nil {
			log.Warnf("cilium metrics about node-to-node connectivity for node %q can not be fetched, the endpoint is not present", n.Name)
			continue
		}
		endpointPathConnectivityStatusType := healthclient.GetPathConnectivityStatusType(endpointPathStatus)
		isEndpointReachable := endpointPathConnectivityStatusType == healthclient.ConnStatusReachable
		isNodeReachable := nodePathConnectivityStatusType == healthclient.ConnStatusReachable
		nodeType := labelValueLocal
		if targetClusterName != localClusterName {
			nodeType = labelValueRemote
		}
		nodeConnectivityStatus.WithLabelValues(localClusterName, localNodeName, targetClusterName, targetNodeName, nodePathStatus.IP, nodeType, labelValueEndpoint).Set(float64(boolToInt32(isEndpointReachable)))
		nodeConnectivityStatus.WithLabelValues(localClusterName, localNodeName, targetClusterName, targetNodeName, nodePathStatus.IP, nodeType, labelValueNode).Set(float64(boolToInt32(isNodeReachable)))
		if endpointPathStatus.HTTP != nil {
			nodeConnectivityLatency.WithLabelValues(localClusterName, localNodeName, targetClusterName, targetNodeName, nodePathStatus.IP, nodeType, labelValueEndpoint, labelValueHTTP).Set(float64(endpointPathStatus.HTTP.Latency))
		} else {
			nodeConnectivityLatency.WithLabelValues(localClusterName, localNodeName, targetClusterName, targetNodeName, nodePathStatus.IP, nodeType, labelValueEndpoint, labelValueHTTP).Set(-1)
		}
		if nodePathStatus.HTTP != nil {
			nodeConnectivityLatency.WithLabelValues(localClusterName, localNodeName, targetClusterName, targetNodeName, nodePathStatus.IP, nodeType, labelValueNode, labelValueHTTP).Set(float64(nodePathStatus.HTTP.Latency))
		} else {
			nodeConnectivityLatency.WithLabelValues(localClusterName, localNodeName, targetClusterName, targetNodeName, nodePathStatus.IP, nodeType, labelValueNode, labelValueHTTP).Set(-1)
		}
		if endpointPathStatus.Icmp != nil {
			nodeConnectivityLatency.WithLabelValues(localClusterName, localNodeName, targetClusterName, targetNodeName, nodePathStatus.IP, nodeType, labelValueEndpoint, labelValueICMP).Set(float64(endpointPathStatus.Icmp.Latency))
		} else {
			nodeConnectivityLatency.WithLabelValues(localClusterName, localNodeName, targetClusterName, targetNodeName, nodePathStatus.IP, nodeType, labelValueEndpoint, labelValueICMP).Set(-1)
		}
		if nodePathStatus.Icmp != nil {
			nodeConnectivityLatency.WithLabelValues(localClusterName, localNodeName, targetClusterName, targetNodeName, nodePathStatus.IP, nodeType, labelValueNode, labelValueICMP).Set(float64(nodePathStatus.Icmp.Latency))
		} else {
			nodeConnectivityLatency.WithLabelValues(localClusterName, localNodeName, targetClusterName, targetNodeName, nodePathStatus.IP, nodeType, labelValueNode, labelValueICMP).Set(-1)
		}
	}

	return nil
}

func main() {
	// Parse command-line flags.
	addr := flag.String("addr", "0.0.0.0:9092", "The 'host:port' at which to expose metrics")
	logLevel := flag.String("log-level", log.InfoLevel.String(), "The level at which to log")
	flag.Parse()

	// Log at the requested level.
	if l, err := log.ParseLevel(*logLevel); err != nil {
		log.Fatalf("Failed to parse log level: %v", err)
	} else {
		log.SetLevel(l)
	}

	log.Infof("extra-cilium-metrics %s", version.Version)

	// Wait for at most 'socketsWaitTimeout' for both Cilium's sockets to be present.
	tc := time.NewTicker(socketsCheckInterval)
	defer tc.Stop()
	tw := time.NewTicker(socketsWaitTimeout)
	defer tw.Stop()
	log.Infof("Waiting for Cilium's socket to be present at %s", ciliumdefaults.SockPath)
loop1:
	for {
		select {
		case <-tc.C:
			if _, err := os.Stat(ciliumdefaults.SockPath); err == nil {
				break loop1
			}
		case <-tw.C:
			log.Fatalf("Cilium's socket not found after %s", socketsWaitTimeout.String())
		}
	}
	log.Infof("Waiting for Cilium's health socket to be present at %s", healthdefaults.SockPath)
loop2:
	for {
		select {
		case <-tc.C:
			if _, err := os.Stat(healthdefaults.SockPath); err == nil {
				break loop2
			}
		case <-tw.C:
			log.Fatalf("Cilium's health socket not found after %s", socketsWaitTimeout.String())
		}
	}

	// Create a client to the Cilium API and attempt to communicate.
	c, err := ciliumclient.NewDefaultClient()
	if err != nil {
		log.Fatalf("Failed to create Cilium client: %v", err)
	}
	d, err := c.Daemon.GetDebuginfo(daemon.NewGetDebuginfoParamsWithContext(context.TODO()))
	if err != nil {
		log.Fatalf("Failed to reach out to Cilium: %v", err)
	}
	// Create a client to the Cilium Health API.
	h, err := healthclient.NewDefaultClient()
	if err != nil {
		log.Fatalf("Failed to create Cilium client: %v", err)
	}

	log.Infof("Cilium %s", d.Payload.CiliumVersion)

	// Configure handling of HTTP requests.
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if err := collectMetrics(c, h); err != nil {
			log.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			log.Trace("Finished collecting metrics, serving...")
			promhttp.Handler().ServeHTTP(w, r)
		}
	})
	log.Fatal(http.ListenAndServe(*addr, nil))
}
