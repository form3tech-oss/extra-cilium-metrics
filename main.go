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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/health/client/connectivity"
	ciliumclient "github.com/cilium/cilium/pkg/client"
	healthclient "github.com/cilium/cilium/pkg/health/client"
	"github.com/form3tech-oss/extra-cilium-metrics/version"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const (
	namespace                 = "cilium_extra"
	labelCluster              = "cluster"
	labelIP                   = "ip"
	labelName                 = "name"
	labelProtocol             = "protocol"
	labelRemote               = "remote"
	labelSelf                 = "self"
	labelType                 = "type"
	labelValueEndpoint        = "endpoint"
	labelValueHTTP            = "http"
	labelValueICMP            = "icmp"
	labelValueNode            = "node"
	subsystemClusterMesh      = "clustermesh"
	subsystemNodeConnectivity = "node_connectivity"
)

var (
	clusterMeshRemoteClusterEtcdHasQuorum = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "Whether the remote cluster's 'cilium-etcd' cluster has quorum",
		Name:      "remote_cluster_etcd_has_quorum",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSelf,
		labelCluster,
	})
	clusterMeshRemoteClusterEtcdTotalObservedLeases = promauto.NewCounterVec(prometheus.CounterOpts{
		Help:      "The total number of observed lease IDs on the remote cluster's 'cilium-etcd' cluster belonging to the current Cilium agent",
		Name:      "remote_cluster_etcd_total_observed_leases",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSelf,
		labelCluster,
	})
	clusterMeshRemoteClusterEtcdTotalObservedLockLeases = promauto.NewCounterVec(prometheus.CounterOpts{
		Help:      "The total number of observed lock lease IDs on the remote cluster's 'cilium-etcd' cluster belonging to the current Cilium agent",
		Name:      "remote_cluster_etcd_total_observed_lock_leases",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSelf,
		labelCluster,
	})
	clusterMeshRemoteClusterLastFailureTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "The timestamp of the last failure of the remote cluster",
		Name:      "remote_cluster_last_failure_timestamp",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSelf,
		labelCluster,
	})
	clusterMeshRemoteClusterReadinessStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "The readiness status of the remote cluster",
		Name:      "remote_cluster_readiness_status",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSelf,
		labelCluster,
	})
	clusterMeshRemoteClusterTotalFailures = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "The total number of failures related to the remote cluster",
		Name:      "remote_cluster_total_failures",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSelf,
		labelCluster,
	})
	clusterMeshRemoteClusterTotalNodes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "The total number of nodes in the remote cluster",
		Name:      "remote_cluster_total_nodes",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSelf,
		labelCluster,
	})
	clusterMeshTotalGlobalServices = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "The total number of global services in the cluster mesh",
		Name:      "total_global_services",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSelf,
	})
	clusterMeshTotalRemoteClusters = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "The total number of remote clusters meshed with the local cluster",
		Name:      "total_remote_clusters",
		Namespace: namespace,
		Subsystem: subsystemClusterMesh,
	}, []string{
		labelSelf,
	})
	nodeConnectivityLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Help:      "The observed latency between the current Cilium agent and other Cilium agents",
		Name:      "latency",
		Namespace: namespace,
		Subsystem: subsystemNodeConnectivity,
		Buckets:   []float64{1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000},
	}, []string{
		labelSelf,
		labelName,
		labelIP,
		labelRemote,
		labelType,
		labelProtocol,
	})
	nodeConnectivityStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Help:      "The status of the connectivity between the current Cilium agent and other Cilium agents",
		Name:      "status",
		Namespace: namespace,
		Subsystem: subsystemNodeConnectivity,
	}, []string{
		labelSelf,
		labelName,
		labelIP,
		labelRemote,
		labelType,
	})
)

var (
	clusterMeshRemoteClusterEtcdStatusRegex = regexp.MustCompile(`^etcd: \d+/\d+ connected, lease-ID=([0-9a-f]+), lock lease-ID=([0-9a-f]+), has-quorum=true`)
)

var (
	lastEtcdLeaseIDs          = make(map[string]string, 0)
	lastEtcdLockLeaseIDs      = make(map[string]string, 0)
	lastConnectivityTimestamp = ""
)

func boolToInt32(v bool) int32 {
	if v {
		return 1
	}
	return 0
}

func collectMetrics(ciliumClient *ciliumclient.Client, healthClient *healthclient.Client) error {
	// Grab information from Cilium's health endpoint.
	h, err := ciliumClient.Daemon.GetHealthz(daemon.NewGetHealthzParamsWithContext(context.TODO()))
	if err != nil {
		return err
	}
	// Collect metrics about an eventual cluster mesh.
	clusterMeshTotalRemoteClusters.WithLabelValues(h.Payload.Cluster.Self).Set(float64(len(h.Payload.ClusterMesh.Clusters)))
	clusterMeshTotalGlobalServices.WithLabelValues(h.Payload.Cluster.Self).Set(float64(h.Payload.ClusterMesh.NumGlobalServices))
	for _, c := range h.Payload.ClusterMesh.Clusters {
		if d := clusterMeshRemoteClusterEtcdStatusRegex.FindStringSubmatch(c.Status); len(d) == 0 {
			clusterMeshRemoteClusterEtcdHasQuorum.WithLabelValues(h.Payload.Cluster.Self, c.Name).Set(0)
		} else {
			clusterMeshRemoteClusterEtcdHasQuorum.WithLabelValues(h.Payload.Cluster.Self, c.Name).Set(1)
			if d[1] != lastEtcdLeaseIDs[c.Name] {
				lastEtcdLeaseIDs[c.Name] = d[1]
				clusterMeshRemoteClusterEtcdTotalObservedLeases.WithLabelValues(h.Payload.Cluster.Self, c.Name).Inc()
			}
			if d[2] != lastEtcdLockLeaseIDs[c.Name] {
				lastEtcdLockLeaseIDs[c.Name] = d[2]
				clusterMeshRemoteClusterEtcdTotalObservedLockLeases.WithLabelValues(h.Payload.Cluster.Self, c.Name).Inc()
			}
		}
		clusterMeshRemoteClusterLastFailureTimestamp.WithLabelValues(h.Payload.Cluster.Self, c.Name).Set(float64(time.Time(c.LastFailure).UnixNano()))
		clusterMeshRemoteClusterReadinessStatus.WithLabelValues(h.Payload.Cluster.Self, c.Name).Set(float64(boolToInt32(c.Ready)))
		clusterMeshRemoteClusterTotalFailures.WithLabelValues(h.Payload.Cluster.Self, c.Name).Set(float64(c.NumFailures))
		clusterMeshRemoteClusterTotalNodes.WithLabelValues(h.Payload.Cluster.Self, c.Name).Set(float64(c.NumNodes))
	}

	// Collect metrics about node-to-node connectivity.
	c, err := healthClient.Connectivity.GetStatus(connectivity.NewGetStatusParamsWithContext(context.TODO()))
	if err != nil {
		return err
	}
	if c.Payload.Timestamp != lastConnectivityTimestamp {
		lastConnectivityTimestamp = c.Payload.Timestamp
		currentClusterName := strings.Split(h.Payload.Cluster.Self, "/")[0]
		for _, n := range c.Payload.Nodes {
			nodePathStatus := healthclient.GetHostPrimaryAddress(n)
			nodePathConnectivityStatusType := healthclient.GetPathConnectivityStatusType(nodePathStatus)
			endpointPathStatus := n.Endpoint
			endpointPathConnectivityStatusType := healthclient.GetPathConnectivityStatusType(endpointPathStatus)
			isRemote := strconv.FormatBool(!strings.HasPrefix(n.Name, currentClusterName+"/"))
			isEndpointReachable := endpointPathConnectivityStatusType == healthclient.ConnStatusReachable
			isNodeReachable := nodePathConnectivityStatusType == healthclient.ConnStatusReachable
			nodeConnectivityStatus.WithLabelValues(h.Payload.Cluster.Self, n.Name, endpointPathStatus.IP, isRemote, labelValueEndpoint).Set(float64(boolToInt32(isEndpointReachable)))
			nodeConnectivityStatus.WithLabelValues(h.Payload.Cluster.Self, n.Name, nodePathStatus.IP, isRemote, labelValueNode).Set(float64(boolToInt32(isNodeReachable)))
			nodeConnectivityLatency.WithLabelValues(h.Payload.Cluster.Self, n.Name, nodePathStatus.IP, isRemote, labelValueEndpoint, labelValueHTTP).Observe(float64(time.Duration(endpointPathStatus.HTTP.Latency).Milliseconds()))
			nodeConnectivityLatency.WithLabelValues(h.Payload.Cluster.Self, n.Name, nodePathStatus.IP, isRemote, labelValueEndpoint, labelValueICMP).Observe(float64(time.Duration(endpointPathStatus.Icmp.Latency).Milliseconds()))
			nodeConnectivityLatency.WithLabelValues(h.Payload.Cluster.Self, n.Name, nodePathStatus.IP, isRemote, labelValueNode, labelValueHTTP).Observe(float64(time.Duration(nodePathStatus.HTTP.Latency).Milliseconds()))
			nodeConnectivityLatency.WithLabelValues(h.Payload.Cluster.Self, n.Name, nodePathStatus.IP, isRemote, labelValueNode, labelValueICMP).Observe(float64(time.Duration(nodePathStatus.Icmp.Latency).Milliseconds()))
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

	log.Infof("extra-cilium-metrics %s (Cilium %s)", version.Version, d.Payload.CiliumVersion)

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
