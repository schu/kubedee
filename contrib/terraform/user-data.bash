#!/bin/bash

set -euo pipefail

# Find debug output in /var/log/cloud-init-output.log
set -x

id -u ubuntu &>/dev/null || adduser --disabled-password ubuntu
usermod -a -G lxd,sudo ubuntu
echo "%sudo ALL=(ALL) NOPASSWD:ALL" >>/etc/sudoers.d/10-sudo-group-nopasswd

apt-get update

apt-get install -y \
  jq \
  lxd \
  lxd-client

lxd init --auto --storage-backend btrfs

curl -fsSL https://files.schu.io/pub/cfssl/cfssl-linux-amd64-1.3.2 -o /tmp/cfssl &&
  install -m 0755 /tmp/cfssl /usr/local/bin/
curl -fsSL https://files.schu.io/pub/cfssl/cfssljson-linux-amd64-1.3.2 -o /tmp/cfssljson &&
  install -m 0755 /tmp/cfssljson /usr/local/bin/

readonly k8s_latest="$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)"
curl -fsSL "https://storage.googleapis.com/kubernetes-release/release/${k8s_latest}/bin/linux/amd64/kubectl" -o /tmp/kubectl &&
  install -m 755 /tmp/kubectl /usr/local/bin/
