# kubedee (beta)

Fast multi-node Kubernetes development and test clusters on [LXD](https://github.com/lxc/lxd).

Under the hood, [CRI-O](https://github.com/kubernetes-incubator/cri-o) is used
as container runtime and [Flannel](https://github.com/coreos/flannel) for
networking.

## Requirements

* [LXD](https://github.com/lxc/lxd)
  * Make sure your user is member of the `lxd` group (see `lxd --group ...`)
  * btrfs is used a storage driver currently and thus `btrfs-{progs,tools}` required
* [cfssl](https://github.com/cloudflare/cfssl) with cfssljson
* [jq](https://stedolan.github.io/jq/)
* kubectl

## Installation

kubedee is meant to and easily installed out of git. Clone the repistory
and link `kubedee` from a directory in your `$PATH`. Example:

```
cd ~/code
git clone https://github.com/schu/kubedee
cd ~/bin
ln -s ~/code/kubedee/kubedee
```

kubedee stores all data in `~/.local/share/kubedee/...`. kubedee LXD resources
have a `kubedee-` prefix.

`KUBEDEE_DEBUG=1` enables verbose debugging output (`set -x`).

## Usage

Example:

```
cd $GOPATH/src/github.com/kubernetes/kubernetes
git checkout v1.9.0
make
[...]
kubedee up test
[...]
eval $(kubedee kubectl-env test)
kubectl get nodes
```

## Smoke test

```
./scripts/configure-service-route
./scripts/smoke-test
```

## Known issues yet to be fixed

* `error: unable to recognize "STDIN": no matches for rbac.authorization.k8s.io/, Kind=ClusterRole`
  Make sure the apiserver is ready before apply.
