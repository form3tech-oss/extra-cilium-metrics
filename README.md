# extra-cilium-metrics

An exporter of extra Cilium metrics in Prometheus format.

The purpose of `extra-cilium-metrics` is to provide extra cilium metrics which are not exposed by [built-in Prometheus exporter](https://docs.cilium.io/en/v1.9/operations/metrics/).

Extra metrics were hand picked based on their usefulness to us. Data for them is provided by Cilium API but they are not exposed as Prometheus metric.
Collection of metrics is synchronous operation, aka there will be collected from cilium at the `/metrics` handler invocation.

The application is meant to be run as cilium agent k8s pod sidecar.

List of metrics

| Name                                             | Description                                                                                                                     |
|--------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| `remote_cluster_etcd_has_quorum`                 | Whether the remote cluster's 'cilium-etcd' cluster has quorum                                                                   |
| `remote_cluster_etcd_total_observed_leases`      | The total number of observed lease IDs on the remote cluster's 'cilium-etcd' cluster belonging to the current Cilium agent      |
| `remote_cluster_etcd_total_observed_lock_leases` | The total number of observed lock lease IDs on the remote cluster's 'cilium-etcd' cluster belonging to the current Cilium agent |
| `remote_cluster_last_failure_timestamp`          | The timestamp of the last failure of the remote cluster                                                                         |
| `remote_cluster_readiness_status`                | The readiness status of the remote cluster                                                                                      |
| `remote_cluster_total_failures`                  | The total number of failures related to the remote cluster                                                                      |
| `remote_cluster_total_nodes`                     | The total number of nodes in the remote cluster                                                                                 |
| `total_global_services`                          | The total number of global services in the cluster mesh                                                                         |
| `total_remote_clusters`                          | The total number of remote clusters meshed with the local cluster                                                               |
| `latency`                                        | The last observed latency (in nanoseconds) between the current Cilium agent and other Cilium agents                             |
| `status`                                         | The last observed status of the connectivity between the current Cilium agent and other Cilium agents                           |
