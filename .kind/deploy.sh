#!/bin/bash

set -a
source $(dirname "${BASH_SOURCE[0]}")/.env
set +a

export KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.15.0}
export KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-kind}

export KIND_API_PORT=${KIND_API_PORT:-6443}
export KIND_API_SERVER=${KIND_API_SERVER:-localhost}
export KIND_NETWORK_NAME=${KIND_NETWORK_NAME:-kubernetes}

export KIND_POD_SUBNET=${KIND_POD_SUBNET:-10.244.0.0/16}
export KIND_SERVICE_SUBNET=${KIND_SERVICE_SUBNET:-10.96.0.0/12}
export KIND_MASTER_SIZE=${KIND_MASTER_SIZE:-2}
export KIND_WORKER_SIZE=${KIND_WORKER_SIZE:-3}

msg_info () {
    echo "[ Info] $*"
}

msg_error () {
    echo "[Error] $*"
    exit 1
}

kind_create_node () {
    name=$1
    role=$2

    shift 2

    cid=$(docker run \
        --detach \
        --hostname $name \
        --label com.progamesigner.kind.cluster=$KIND_CLUSTER_NAME \
        --label com.progamesigner.kind.role=$role \
        --label io.k8s.sigs.kind.cluster=$KIND_CLUSTER_NAME \
        --label io.k8s.sigs.kind.role=$role \
        --network $KIND_NETWORK_NAME \
        --privileged \
        --security-opt seccomp=unconfined \
        --tmpfs /run \
        --tmpfs /tmp \
        --volume /lib/modules:/lib/modules:ro \
        $KIND_NODE_FLAGS "$@" $KIND_NODE_IMAGE
    )
    if [ $? -ne 0 ]; then
        msg_error "Failed to create node ($name)"
    fi

    ret=$(docker exec $cid sysctl net.ipv6.conf.all.disable_ipv6=0)
    if [ $? -ne 0 ]; then
        msg_error "Failed to enable ipv6"
    fi

    ret=$(docker exec $cid sysctl net.ipv6.conf.all.forwarding=1)
    if [ $? -ne 0 ]; then
        msg_error "Failed to enable ipv6 forwarding"
    fi
}

kind_get_address () {
    echo "$(docker inspect \
        --format "{{ range .NetworkSettings.Networks }}{{ .IPAddress }}{{ end }}" \
        $1
    )"
}

kind_hup_node () {
    ret=$(docker kill --signal SIGHUP "$@")
}

kind_select_nodes () {
    echo "$(docker ps \
        --quiet \
        --filter "label=com.progamesigner.kind.role=$1" \
        --format "{{ .ID }}"
    )"
}

kind_write_file () {
    node=$1
    path=$2

    ret=$(docker exec $node mkdir -p $(dirname $path))
    if [ $? -ne 0 ]; then
        msg_error "Failed to create directory '$(dirname $path)'"
    fi

    ret=$(cat /dev/stdin | docker exec --interactive $node cp /dev/stdin $path)
}

msg_info "Creating kubernetes cluster ..."

ret=$(docker network inspect $KIND_NETWORK_NAME)
if [ $? -ne 0 ]; then
    msg_info "Creating network '$KIND_NETWORK_NAME' ..."
    ret=$(docker network create $KIND_NETWORK_NAME)
    if [ $? -ne 0 ]; then
        msg_error "failed to create network '$KIND_NETWORK_NAME'"
    fi
fi

msg_info "Ensuring node image ($KIND_NODE_IMAGE) 🖼 ..."

ret=$(docker pull $KIND_NODE_IMAGE)
if [ $? -ne 0 ]; then
    msg_error "failed to pull node image ($KIND_NODE_IMAGE)"
fi

msg_info "Preparing nodes 📦 ..."

for i in $(seq 1 $KIND_MASTER_SIZE); do
    kind_create_node \
        "kind-master-$i" \
        "control-plane" \
        --expose $KIND_API_PORT \
        &
done

for i in $(seq 1 $KIND_WORKER_SIZE); do
    kind_create_node \
        "kind-worker-$i" \
        "worker" \
        &
done

loadbalancer_node=$(docker run \
    --detach \
    --expose 443/tcp \
    --expose 80/tcp \
    --hostname kubernetes-loadbalancer \
    --label com.progamesigner.kind.cluster=$KIND_CLUSTER_NAME \
    --label com.progamesigner.kind.role=loadbalancer \
    --label io.k8s.sigs.kind.cluster=$KIND_CLUSTER_NAME \
    --label io.k8s.sigs.kind.role=loadbalancer \
    --network $KIND_NETWORK_NAME \
    --publish $KIND_API_PORT:$KIND_API_PORT \
    $KIND_LOADBALANCER_FLAGS kindest/haproxy:2.0.0-alpine
)
if [ $? -ne 0 ]; then
    msg_error "Failed to create load balancer"
fi

wait

msg_info "Configuring external load balancer ⚖️ ..."

control_plane_nodes=$(kind_select_nodes "control-plane")

control_plane_bootstraper=$(echo "${control_plane_nodes}" | head -n 1)

worker_nodes=$(kind_select_nodes "worker")

echo "
global
  log /dev/log local0
  log /dev/log local1 notice
  daemon

defaults
  log global
  mode tcp
  option dontlognull
  timeout connect 5000
  timeout client 50000
  timeout server 50000

frontend master
  bind *:$KIND_API_PORT
  bind :::$KIND_API_PORT
  default_backend kubernetes-masters

frontend worker
  bind *:80
  bind *:443
  bind :::80
  bind :::443
  default_backend kubernetes-workers

backend kubernetes-masters
$(for node in $control_plane_nodes; do
    echo "  server $node $(kind_get_address $node):$KIND_API_PORT check check-ssl verify none"
done)

backend kubernetes-workers
$(for node in $worker_nodes; do
    echo "  server $node $(kind_get_address $node) check port 80"
done)
" | kind_write_file $loadbalancer_node /usr/local/etc/haproxy/haproxy.cfg
if [ $? -ne 0 ]; then
    msg_error "Failed to copy loadbalancer config to node"
fi

kind_hup_node $loadbalancer_node
if [ $? -ne 0 ]; then
    msg_error "Failed to reload loadbalancer"
fi

msg_info "Creating kubeadm config 📜 ..."

for node in $(echo "$control_plane_nodes" "$worker_nodes"); do
    role=$(docker inspect $node --format "{{ index .Config.Labels \"com.progamesigner.kind.role\" }}")

    echo "
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 208.67.222.222
    " | kind_write_file $node /kind/resolv.conf
    if [ $? -ne 0 ]; then
        msg_error "Failed to copy resolv.conf to node"
    fi

    echo "
apiVersion: kubeadm.k8s.io/v1beta2
kind: ClusterConfiguration
kubernetesVersion: $(docker exec $node cat /kind/version)
clusterName: $KIND_CLUSTER_NAME
controlPlaneEndpoint: $(kind_get_address $loadbalancer_node):$KIND_API_PORT
apiServer:
  certSANs: [localhost, \"$KIND_API_SERVER\"]
controllerManager:
  extraArgs:
    enable-hostpath-provisioner: \"true\"
networking:
  podSubnet: $KIND_POD_SUBNET
  serviceSubnet: $KIND_SERVICE_SUBNET
---
apiVersion: kubeadm.k8s.io/v1beta2
kind: InitConfiguration
bootstrapTokens:
- token: \"abcdef.0123456789abcdef\"
localAPIEndpoint:
  advertiseAddress: $(kind_get_address $node)
  bindPort: $KIND_API_PORT
nodeRegistration:
  criSocket: \"/run/containerd/containerd.sock\"
  kubeletExtraArgs:
    fail-swap-on: \"false\"
    node-ip: $(kind_get_address $node)
---
apiVersion: kubeadm.k8s.io/v1beta2
kind: JoinConfiguration
$(if [ $role == "control-plane" ]; then echo "
controlPlane:
  localAPIEndpoint:
    advertiseAddress: $(kind_get_address $node)
    bindPort: $KIND_API_PORT
"; fi)
nodeRegistration:
  criSocket: /run/containerd/containerd.sock
  kubeletExtraArgs:
    fail-swap-on: \"false\"
    node-ip: $(kind_get_address $node)
discovery:
  bootstrapToken:
    apiServerEndpoint: $(kind_get_address $loadbalancer_node):$KIND_API_PORT
    token: \"abcdef.0123456789abcdef\"
    unsafeSkipCAVerification: true
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
imageGCHighThresholdPercent: 100
evictionHard:
  nodefs.available: \"0%\"
  nodefs.inodesFree: \"0%\"
  imagefs.available: \"0%\"
resolvConf: /kind/resolv.conf
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
" | kind_write_file $node /kind/kubeadm.conf
    if [ $? -ne 0 ]; then
        msg_error "Failed to copy kubeadm config to node"
    fi
done
msg_info "Starting control-plane 🕹️ ..."

# allocate pseudo-TTY to avoid overwhelming messages
ret=$(docker exec \
    --tty \
    $control_plane_bootstraper \
    kubeadm init \
        --ignore-preflight-errors=all \
        --config=/kind/kubeadm.conf \
        --skip-token-print \
        --v=6)
if [ $? -ne 0 ]; then
    msg_error "Failed to init node with kubeadm"
fi

echo "$(docker exec \
    $control_plane_bootstraper \
    cat /etc/kubernetes/admin.conf
)" | cp /dev/stdin ~/.kube/kube_config_$KIND_CLUSTER_NAME
if [ $? -ne 0 ]; then
    msg_error "Failed to copy kubeconfig from node"
fi

msg_info "Installing CNI 🔌 ..."

cni_manifest="
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: kindnet
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: docker/default
    seccomp.security.alpha.kubernetes.io/defaultProfileName: docker/default
    apparmor.security.beta.kubernetes.io/allowedProfileNames: runtime/default
    apparmor.security.beta.kubernetes.io/defaultProfileName: runtime/default
spec:
  privileged: false
  volumes:
  - configMap
  - secret
  - emptyDir
  - hostPath
  allowedHostPaths:
  - pathPrefix: /etc/cni/net.d
  readOnlyRootFilesystem: false
  # Users and groups
  runAsUser:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  # Privilege Escalation
  allowPrivilegeEscalation: false
  defaultAllowPrivilegeEscalation: false
  # Capabilities
  allowedCapabilities: [\"NET_RAW\", \"NET_ADMIN\"]
  defaultAddCapabilities: []
  requiredDropCapabilities: []
  # Host namespaces
  hostPID: false
  hostIPC: false
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  # SELinux
  seLinux:
    rule: RunAsAny
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: kindnet
rules:
- apiGroups:
  - policy
  resources:
  - podsecuritypolicies
  verbs:
  - use
  resourceNames:
  - kindnet
- apiGroups:
  - \"\"
  resources:
  - nodes
  verbs:
  - list
  - watch
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: kindnet
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kindnet
subjects:
- kind: ServiceAccount
  name: kindnet
  namespace: kube-system
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kindnet
  namespace: kube-system
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kindnet
  namespace: kube-system
  labels:
    tier: node
    app: kindnet
    k8s-app: kindnet
spec:
  selector:
    matchLabels:
      app: kindnet
  template:
    metadata:
      labels:
        tier: node
        app: kindnet
        k8s-app: kindnet
    spec:
      hostNetwork: true
      tolerations:
      - operator: Exists
        effect: NoSchedule
      serviceAccountName: kindnet
      containers:
      - name: kindnet-cni
        image: kindest/kindnetd:0.5.0
        env:
        - name: HOST_IP
          valueFrom:
            fieldRef:
              fieldPath: status.hostIP
        - name: POD_IP
          valueFrom:
            fieldRef:
              fieldPath: status.podIP
        - name: POD_SUBNET
          value: $KIND_POD_SUBNET
        volumeMounts:
        - name: cni-cfg
          mountPath: /etc/cni/net.d
        resources:
          requests:
            cpu: \"100m\"
            memory: \"50Mi\"
          limits:
            cpu: \"100m\"
            memory: \"50Mi\"
        securityContext:
          privileged: false
          capabilities:
            add: [\"NET_RAW\", \"NET_ADMIN\"]
      volumes:
      - name: cni-cfg
        hostPath:
          path: /etc/cni/net.d
"
if [ $? -ne 0 ]; then
    msg_error "Failed to read CNI manifest"
fi

ret=$(echo "$cni_manifest" | docker exec \
    --interactive \
    $control_plane_bootstraper \
    kubectl create --kubeconfig=/etc/kubernetes/admin.conf -f -)
if [ $? -ne 0 ]; then
    msg_error "Failed to apply overlay network"
fi

msg_info "Installing StorageClass 💾 ..."

default_storage_class_manifest="
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  namespace: kube-system
  name: standard
  annotations:
    storageclass.beta.kubernetes.io/is-default-class: \"true\"
  labels:
    addonmanager.kubernetes.io/mode: EnsureExists
provisioner: kubernetes.io/host-path
"

ret=$(echo "$default_storage_class_manifest" | docker exec \
    --interactive \
    $control_plane_bootstraper \
    kubectl create --kubeconfig=/etc/kubernetes/admin.conf -f -
)
if [ $? -ne 0 ]; then
    msg_error "Failed to add default storage class"
fi

msg_info "Joining more control-plane nodes 🎮 ..."

tmp_loc=$(mktemp -d -t $KIND_CLUSTER_NAME)

mkdir -p "$tmp_loc/etcd"

for node in $(echo "$control_plane_nodes" | tail -n +2); do
    ret=$(docker exec $node mkdir -p /etc/kubernetes/pki/etcd)
    if [ $? -ne 0 ]; then
        msg_error "Failed to join control plane node with kubeadm"
    fi

    for filename in $(echo "ca.crt ca.key front-proxy-ca.crt front-proxy-ca.key sa.pub sa.key etcd/ca.crt etcd/ca.key"); do
        ret=$(docker cp \
            "$control_plane_bootstraper:/etc/kubernetes/pki/$filename" \
            "$tmp_loc/$filename"
        )
        if [ $? -ne 0 ]; then
            msg_error "Failed to copy certificate $filename"
        fi

        ret=$(docker cp \
            "$tmp_loc/$filename" \
            "$node:/etc/kubernetes/pki/$filename"
        )
        if [ $? -ne 0 ]; then
            msg_error "Failed to copy certificate $filename"
        fi
    done

    ret=$(docker exec \
        --tty \
        $node \
        kubeadm join \
            --config /kind/kubeadm.conf \
            --ignore-preflight-errors=all \
            --v=6
    )
    if [ $? -ne 0 ]; then
        msg_error "Failed to join control plane node with kubeadm"
    fi
done

msg_info "Joining worker nodes 🚜 ..."

for node in $worker_nodes; do
    ret=$(docker exec \
        --tty \
        $node \
        kubeadm join \
            --config /kind/kubeadm.conf \
            --ignore-preflight-errors=all \
            --v=6 &)
    if [ $? -ne 0 ]; then
        msg_error "Failed to join worker node with kubeadm"
    fi
done

msg_info "Waiting for nodes ready ⏳ ..."

wait

is_waiting_cluster=true
while $is_waiting_cluster; do
    is_waiting_cluster=false

    lines=$(docker exec \
        $control_plane_bootstraper \
        kubectl \
            --kubeconfig=/etc/kubernetes/admin.conf \
            get nodes \
                --selector=node-role.kubernetes.io/master \
                -o=jsonpath='{.items..status.conditions[-1:].status}'
    )

    for status in $lines; do
        ret=$(echo "$status" | grep "True")
        if [ $? -ne 0 ]; then
            is_waiting_cluster=true
        fi
    done
done

rm -r $tmp_loc

msg_info "Cluster is ready 💚"
