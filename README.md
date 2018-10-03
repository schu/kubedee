# kubedee (beta)

Fast multi-node Kubernetes (>= 1.10) development and test clusters on [LXD](https://github.com/lxc/lxd).

Under the hood, [CRI-O](https://github.com/kubernetes-incubator/cri-o) is used
as container runtime and [Flannel](https://github.com/coreos/flannel) for
networking.

For questions or feedback, please open an issue or join `#kubedee` on [freenode].

## Requirements

* [LXD](https://github.com/lxc/lxd) (The author currently uses `stable-3.0` [installed from source](https://lxd.readthedocs.io/en/latest/#installing-lxd-from-source))
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

That's it!

kubedee stores all data in `~/.local/share/kubedee/...`. kubedee LXD resources
have a `kubedee-` prefix.

`KUBEDEE_DEBUG=1` enables verbose debugging output (`set -x`).

## Usage

### Getting started

kubedee can install clusters based on an upstream version of Kubernetes
or your own build.

To install an upstream version, use `--kubernetes-version` to specify
the release (Git tag) that you want to install. For example:

```
kubedee up test --kubernetes-version v1.12.0
```

To install a local build, specify the location of the binaries
(`kube-apiserver` etc.) with `--bin-dir`. For example:

```
kubedee up test --bin-dir /path/to/my/kubernetes/binaries
```

The default for `--bin-dir` is `./_output/bin/` and thus matches the
default location after running `make` in the Kubernetes repository.
So in a typical development workflow `--bin-dir` doesn't need to be
specified.

Note: after the installation or upgrade of kubedee, kubedee requires some
extra time to download and update cached packages and images once.

With a SSD, up-to-date caches and images, setting up a cluster usually takes
less than 60 seconds for a four node cluster (etcd, controller, 2x worker).

```
[...]

Cluster test started
kubectl config current-context set to kubedee-test

Cluster nodes can be accessed with 'lxc exec <name> bash'
Cluster files can be found in '/home/schu/.local/share/kubedee/clusters/test'

Current component status is (should be healthy):
NAME                 STATUS    MESSAGE             ERROR
scheduler            Healthy   ok
controller-manager   Healthy   ok
etcd-0               Healthy   {"health":"true"}

Current node status is (should be ready soon):
NAME                         STATUS     ROLES     AGE       VERSION
kubedee-test-controller      NotReady   master    24s       v1.11.2
kubedee-test-worker-l1tdqq   NotReady   <none>    16s       v1.11.2
kubedee-test-worker-tx8q8f   NotReady   <none>    8s        v1.11.2
```

kubectl's current-context has been changed to the new cluster automatically.

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

Configure the `kubectl` env:

```
eval $(kubedee kubectl-env <cluster-name>)
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

kubedee has a `smoke-test` subcommand:

```
kubedee smoke-test <cluster-name>
```

[freenode]: https://freenode.net/
