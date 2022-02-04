# Kubernetes in Docker

```sh
./.kind/deploy.sh
```

- The node image comes from [kind](https://kind.sigs.k8s.io/) project.

## Install & Deploy Tools

### CLI: kubectl and helm

```sh
brew install kubernetes-cli # Homebrew
brew install kubernetes-helm # Homebrew
```

### Helm (tiller)

```sh
kubectl create serviceaccount tiller --namespace=kube-system
kubectl create clusterrolebinding tiller --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
helm init --service-account=tiller
helm repo add incubator https://kubernetes-charts-incubator.storage.googleapis.com/
```

### MetalLB (in bare-metal)

*Install MetalLB in bare-metal environment for on-premise load balancer*

```sh
kubectl create configmap metallb-config \
    --namespace=metallb-system \
    --from-file=config=metallb-config.yaml
helm upgrade metallb stable/metallb \
    --install \
    --namespace=metallb-system
```

### Nginx Ingress

If MetalLB is used:
```sh
helm upgrade nginx-ingress stable/nginx-ingress \
    --install \
    --namespace=nginx-ingress
```

Otherwise (in KinD):
```sh
helm upgrade nginx-ingress stable/nginx-ingress \
    --install \
    --namespace=nginx-ingress \
    --set=controller.daemonset.useHostPort=true \
    --set=controller.kind=DaemonSet \
    --set=controller.service.type=NodePort
```

### Kubernetes Dashbaord

```sh
helm upgrade kubernetes-dashboard stable/kubernetes-dashboard \
    --install \
    --namespace=kube-dashboard \
    --set=enableInsecureLogin=true \
    --set=enableSkipLogin=true \
    --set=ingress.enabled=true \
    --set=ingress.hosts[0]=<HOST_NAME> \
    --set=rbac.clusterAdminRole=true \
    --set=serviceAccount.create=true \
    --set=serviceAccount.name=dashbaord-admin
```

#### Get dashboard token

```sh
kubectl -n kube-system describe secret $(kubectl -n kube-dashbaord get secret | grep dashbaord-admin | awk '{print $1}')
```
