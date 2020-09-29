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
	"time"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/pkg/client"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const (
	namespace            = "cilium_extra"
	labelCluster         = "cluster"
	labelSelf            = "self"
	subsystemClusterMesh = "clustermesh"
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

func collectMetrics(ciliumClient *client.Client) error {
	// Grab information from Cilium's health endpoint.
	r, err := ciliumClient.Daemon.GetHealthz(daemon.NewGetHealthzParamsWithContext(context.TODO()))
	if err != nil {
		return err
	}
	// Collect metrics about an eventual cluster mesh.
	n := r.Payload.Cluster.Self
	m := r.Payload.ClusterMesh
	clusterMeshTotalRemoteClusters.WithLabelValues(n).Set(float64(len(m.Clusters)))
	clusterMeshTotalGlobalServices.WithLabelValues(n).Set(float64(m.NumGlobalServices))
	for _, c := range m.Clusters {
		if d := clusterMeshRemoteClusterEtcdStatusRegex.FindStringSubmatch(c.Status); len(d) == 0 {
			clusterMeshRemoteClusterEtcdHasQuorum.WithLabelValues(n, c.Name).Set(0)
		} else {
			clusterMeshRemoteClusterEtcdHasQuorum.WithLabelValues(n, c.Name).Set(1)
			if d[1] != lastEtcdLeaseIDs[c.Name] {
				lastEtcdLeaseIDs[c.Name] = d[1]
				clusterMeshRemoteClusterEtcdTotalObservedLeases.WithLabelValues(n, c.Name).Inc()
			}
			if d[2] != lastEtcdLockLeaseIDs[c.Name] {
				lastEtcdLockLeaseIDs[c.Name] = d[2]
				clusterMeshRemoteClusterEtcdTotalObservedLockLeases.WithLabelValues(n, c.Name).Inc()
			}
		}
		clusterMeshRemoteClusterLastFailureTimestamp.WithLabelValues(n, c.Name).Set(float64(time.Time(c.LastFailure).UnixNano()))
		clusterMeshRemoteClusterReadinessStatus.WithLabelValues(n, c.Name).Set(float64(boolToInt32(c.Ready)))
		clusterMeshRemoteClusterTotalFailures.WithLabelValues(n, c.Name).Set(float64(c.NumFailures))
		clusterMeshRemoteClusterTotalNodes.WithLabelValues(n, c.Name).Set(float64(c.NumNodes))
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
	c, err := client.NewDefaultClient()
	if err != nil {
		log.Fatalf("Failed to create Cilium client: %v", err)
	}
	d, err := c.Daemon.GetDebuginfo(daemon.NewGetDebuginfoParamsWithContext(context.TODO()))
	if err != nil {
		log.Fatalf("Failed to reach out to Cilium: %v", err)
	}
	log.Debugf("Cilium version: %s", d.Payload.CiliumVersion)

	// Configure handling of HTTP requests.
	h := promhttp.Handler()
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if err := collectMetrics(c); err != nil {
			log.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			log.Trace("Finished collecting metrics, serving...")
			h.ServeHTTP(w, r)
		}
	})
	log.Fatal(http.ListenAndServe(*addr, nil))
}
