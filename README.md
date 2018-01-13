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

### Getting started

First, build the version of k8s that you want to setup (or [download the server
binaries](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG-1.9.md#server-binaries)).
By default, kubedee looks for k8s executables in `./_output/bin/`.
Alternatively, you can point kubedee to a directory with `--bin-dir`.

```
cd $GOPATH/src/github.com/kubernetes/kubernetes
git checkout v1.9.1
make
[...]
```

Create and start a new cluster with name "test".

```
kubedee up test
[...]
```

Note: after the installation or upgrade of kubedee, kubedee requires some
extra time to download and update cached packages and images once.

With a SSD, up-to-date caches and images, setting up a cluster usually takes
less than 60 seconds for a four node cluster (etcd, controller, 2x worker).

```
[...]

Cluster test started
Run the following command to use kubectl with the new cluster:

        export KUBECONFIG=/home/schu/.local/share/kubedee/clusters/test/kubeconfig/admin.kubeconfig

Cluster nodes can be accessed with 'lxc exec <name> bash'
Cluster files can be found in '/home/schu/.local/share/kubedee/clusters/test'

Current component status is (should be healthy):
NAME                 STATUS    MESSAGE              ERROR
scheduler            Healthy   ok
controller-manager   Healthy   ok
etcd-0               Healthy   {"health": "true"}

Current node status is (should be ready soon):
NAME                        STATUS     ROLES     AGE       VERSION
kubedee-test-worker-i7k3n1   Ready      <none>    11s       v1.9.1
kubedee-test-worker-lp2cno   NotReady   <none>    6s        v1.9.1
```

Finally, configure the current shell to use the new cluster:

```
eval $(kubedee kubectl-env test)
```

### Cheatsheet

List the available clusters:

```
kubedee [list]
```

Start a cluster with less/more worker nodes than the default of 2:

```
kubedee up --num-workers 4 <cluster-name>
```

Start a new worker node in an existing cluster:

```
kubedee start-worker <cluster-name>
```

Delete a cluster:

```
kubedee delete <cluster-name>
```

Configure the `etcdctl` env:

```
eval $(kubedee etcd-env <cluster-name>)
```

See all available commands and options:

```
kubedee help
```

## Smoke test

```
./scripts/configure-service-route
./scripts/smoke-test
```

## Known issues yet to be fixed

* `error: unable to recognize "STDIN": no matches for rbac.authorization.k8s.io/, Kind=ClusterRole`
  Make sure the apiserver is ready before apply.
