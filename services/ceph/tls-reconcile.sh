#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

NAMESPACE=${POD_NAMESPACE:-default}
TRUST=tls-ceph-radosgw-client-trust
HOSTNAME=radosgw.default.svc.cluster.local
ANNOTATION=tls.progamesigner.dev/content-sha256
CLIENTS=(seafile-backend seafile-frontend seafile-metadata seafile-thumbnail)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
trap 'echo "TLS reconciliation failed at line $LINENO" >&2' ERR

fail() {
  echo "$*" >&2
  exit 1
}

api() {
  local method=$1 kind=$2 name=$3 prefix resource
  local account=/var/run/secrets/kubernetes.io/serviceaccount
  case $kind in
    configmap) prefix=api/v1; resource=configmaps ;;
    secret) prefix=api/v1; resource=secrets ;;
    endpoints) prefix=api/v1; resource=endpoints ;;
    deployment) prefix=apis/apps/v1; resource=deployments ;;
    *) return 1 ;;
  esac
  printf 'Authorization: Bearer %s\n' "$(< "$account/token")" > "$WORK/headers" || return
  shift 3
  curl --fail --silent --show-error --connect-timeout 5 --max-time 20 \
    --cacert "$account/ca.crt" --header @"$WORK/headers" --request "$method" \
    "https://kubernetes.default.svc/$prefix/namespaces/$NAMESPACE/$resource/$name" "$@"
}

patch() {
  api PATCH "$1" "$2" --header 'Content-Type: application/merge-patch+json' \
    --data-binary @"$WORK/patch.json" --output /dev/null
}

checksum() {
  sha256sum | cut -d ' ' -f 1
}

fingerprint() {
  openssl x509 -in "$1" -outform DER | checksum
}

sync_deployment() {
  local name=$1 expected=$2 current
  api GET deployment "$name" > "$WORK/deployment.json" || return
  current=$(jq -r --arg key "$ANNOTATION" '.spec.template.metadata.annotations[$key] // ""' \
    "$WORK/deployment.json") || return
  if [[ $current != "$expected" ]]; then
    jq --arg key "$ANNOTATION" --arg value "$expected" '
      {metadata: {resourceVersion: .metadata.resourceVersion},
       spec: {template: {metadata: {annotations: {($key): $value}}}}}
    ' "$WORK/deployment.json" > "$WORK/patch.json" || return
    patch deployment "$name" || return
    echo "Requested $name reload"
  fi
}

deployment_ready() {
  local name=$1 expected=$2
  api GET deployment "$name" > "$WORK/deployment.json" || return
  jq -e --arg key "$ANNOTATION" --arg value "$expected" '
    (.spec.replicas // 1) as $n |
    .spec.template.metadata.annotations[$key] == $value and
    (.status.observedGeneration // 0) >= .metadata.generation and
    (.status.updatedReplicas // 0) == $n and
    (.status.readyReplicas // 0) == $n and
    (.status.availableReplicas // 0) == $n and
    (.status.replicas // 0) == $n
  ' "$WORK/deployment.json" > /dev/null
}

retry_rgw() {
  api GET deployment ceph-radosgw > "$WORK/deployment.json"
  jq --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
    {metadata: {resourceVersion: .metadata.resourceVersion},
     spec: {template: {metadata: {annotations: {"tls.progamesigner.dev/retry-at": $time}}}}}
  ' "$WORK/deployment.json" > "$WORK/patch.json"
  patch deployment ceph-radosgw
  fail 'RGW served stale material; requested a fresh reload for the next check'
}

assert_sources() {
  api GET secret tls-ceph-radosgw > "$WORK/latest.json"
  jq -e --slurpfile original "$WORK/secret.json" '
    .data as $now | $original[0].data as $before |
    ["tls.crt", "tls.key", "ca.crt"] | all(.[]; $now[.] == $before[.])
  ' "$WORK/latest.json" > /dev/null || fail 'Source changed during rollout; retry next run'
  api GET configmap "$TRUST" > "$WORK/latest-trust.json"
  jq -e --rawfile ca "$WORK/ca.crt" '.data["ca.crt"] == $ca' "$WORK/latest-trust.json" \
    > /dev/null || fail 'Trust changed during rollout; retry next run'
}

api GET secret tls-ceph-radosgw > "$WORK/secret.json"
jq -er '.data["tls.crt"]' "$WORK/secret.json" | base64 -d > "$WORK/tls.crt"
jq -er '.data["tls.key"]' "$WORK/secret.json" | base64 -d > "$WORK/tls.key"
jq -er '.data["ca.crt"]' "$WORK/secret.json" | base64 -d > "$WORK/ca.crt"
openssl x509 -in "$WORK/tls.crt" -pubkey -noout > "$WORK/cert-public.pem"
openssl pkey -in "$WORK/tls.key" -pubout > "$WORK/key-public.pem"
cmp "$WORK/cert-public.pem" "$WORK/key-public.pem"
openssl verify -purpose sslserver -verify_hostname "$HOSTNAME" -CAfile "$WORK/ca.crt" \
  -untrusted "$WORK/tls.crt" "$WORK/tls.crt"
LEAF_HASH=$(cat "$WORK/tls.crt" "$WORK/tls.key" | checksum)
TRUST_HASH=$(checksum < "$WORK/ca.crt")

api GET configmap "$TRUST" > "$WORK/trust.json"
if ! jq -e --rawfile ca "$WORK/ca.crt" '.data["ca.crt"] == $ca' "$WORK/trust.json" > /dev/null; then
  jq --rawfile ca "$WORK/ca.crt" '
    {metadata: {resourceVersion: .metadata.resourceVersion}, data: {"ca.crt": $ca}}
  ' "$WORK/trust.json" > "$WORK/patch.json"
  patch configmap "$TRUST"
fi

sync_deployment ceph-radosgw "$LEAF_HASH" || echo 'Could not request RGW reload; checking convergence' >&2
for name in "${CLIENTS[@]}"; do
  sync_deployment "$name" "$TRUST_HASH" || echo "Could not request $name reload; checking convergence" >&2
done

deadline=$((SECONDS + ${ROLLOUT_TIMEOUT_SECONDS:-240}))
while ! deployment_ready ceph-radosgw "$LEAF_HASH"; do
  (( SECONDS < deadline )) || fail 'RGW rollout still pending; retry next run'
  sleep 10
done

assert_sources

api GET deployment ceph-radosgw > "$WORK/deployment.json"
expected=$(jq -er '.spec.replicas // 1' "$WORK/deployment.json")
if (( expected > 0 )); then
  api GET endpoints radosgw > "$WORK/endpoints.json"
  jq -e '[.subsets[]?.notReadyAddresses[]?] | length == 0' "$WORK/endpoints.json" > /dev/null
  count=$(jq '[.subsets[]?.addresses[]?] | unique_by(.ip) | length' "$WORK/endpoints.json")
  (( count == expected )) || fail 'RGW endpoint count does not match its desired replicas'
  jq -r '[.subsets[]?.addresses[]?.ip] | unique[]' "$WORK/endpoints.json" > "$WORK/addresses"
  expected_cert=$(fingerprint "$WORK/tls.crt")
  while IFS= read -r address; do
    connect=$address:8443
    [[ $address != *:* ]] || connect=[$address]:8443
    verified=1
    timeout 15 openssl s_client -connect "$connect" -servername "$HOSTNAME" \
      -verify_hostname "$HOSTNAME" -verify_return_error -CAfile "$WORK/ca.crt" -showcerts \
      < /dev/null > "$WORK/served.pem" 2> "$WORK/handshake.log" || verified=0
    if served_cert=$(fingerprint "$WORK/served.pem" 2> /dev/null); then
      [[ $served_cert == "$expected_cert" ]] || retry_rgw
    else
      fail "RGW endpoint $address did not present a certificate"
    fi
    (( verified == 1 )) || fail "RGW endpoint $address failed TLS verification"
  done < "$WORK/addresses"
else
  echo 'RGW is scaled to zero; skipping endpoint TLS checks'
fi

while :; do
  pending=()
  for name in "${CLIENTS[@]}"; do
    deployment_ready "$name" "$TRUST_HASH" || pending+=("$name")
  done
  (( ${#pending[@]} > 0 )) || break
  (( SECONDS < deadline )) || fail "Client rollouts still pending: ${pending[*]}; retry next run"
  sleep 10
done

assert_sources

openssl x509 -in "$WORK/tls.crt" -checkend 1209600 -noout || fail 'RGW leaf expires within 14 days'
openssl x509 -in "$WORK/ca.crt" -checkend 2592000 -noout || fail 'Active CA expires within 30 days'
if (( expected > 0 )); then
  echo 'All rollouts and RGW endpoint TLS checks passed'
else
  echo 'All requested rollouts completed; RGW is scaled to zero'
fi
