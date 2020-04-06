#!/bin/bash

set -euo pipefail

# Find debug output in /var/log/cloud-init-output.log
set -x

id -u ubuntu &>/dev/null || adduser --disabled-password --gecos '' ubuntu
echo "%sudo ALL=(ALL) NOPASSWD:ALL" >>/etc/sudoers.d/10-sudo-group-nopasswd

apt-get update

apt-get install -y \
  jq \
  lxd \
  lxd-client

lxd init --auto --storage-backend btrfs

usermod -a -G lxd,sudo ubuntu

curl -fsSL https://github.com/cloudflare/cfssl/releases/download/v1.4.1/cfssl_1.4.1_linux_amd64 -o /tmp/cfssl &&
  install -m 0755 /tmp/cfssl /usr/local/bin/
curl -fsSL https://github.com/cloudflare/cfssl/releases/download/v1.4.1/cfssl_1.4.1_linux_amd64 -o /tmp/cfssljson &&
  install -m 0755 /tmp/cfssljson /usr/local/bin/

readonly k8s_latest="$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)"
curl -fsSL "https://storage.googleapis.com/kubernetes-release/release/${k8s_latest}/bin/linux/amd64/kubectl" -o /tmp/kubectl &&
  install -m 755 /tmp/kubectl /usr/local/bin/
