#!/usr/bin/env bash

set -euxo pipefail

CILIUM_NAMESPACE="${1}"
BINARY="${2}"

CILIUM_AGENT_CONTAINER="cilium-agent"
BINARY_NAME="$(basename "${BINARY}")"
REMOTE_BINARY_PATH="/tmp/${BINARY_NAME}"

CILIUM_POD=$(kubectl -n "${CILIUM_NAMESPACE}" get pod -l k8s-app=cilium -o jsonpath='{.items[0].metadata.name}' --sort-by metadata.name)
kubectl -n "${CILIUM_NAMESPACE}" cp -c "${CILIUM_AGENT_CONTAINER}" "${BINARY}" "${CILIUM_POD}:${REMOTE_BINARY_PATH}"
kubectl -n "${CILIUM_NAMESPACE}" port-forward "${CILIUM_POD}" 9092:9092 &
PID="${!}"
trap 'kill ${PID}' SIGINT SIGTERM EXIT

kubectl -n "${CILIUM_NAMESPACE}" exec -c "${CILIUM_AGENT_CONTAINER}" -it "${CILIUM_POD}" -- pkill -f ${BINARY_NAME} || true
kubectl -n "${CILIUM_NAMESPACE}" exec -c "${CILIUM_AGENT_CONTAINER}" -it "${CILIUM_POD}" -- "${REMOTE_BINARY_PATH}" --log-level trace
