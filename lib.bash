#!/bin/bash

# Expected variables:
#   $kubedee_source_dir The directory where kubedee's source code is (i.e. git repo)
#   $kubedee_dir The directory to store kubedee's internal data
#   $kubedee_version The kubedee version, used for the cache
#   $kubedee_image Name for the LXD image
#   $lxc_init_opts Additional LXC container creation options

kubedee::log_info() {
  local -r message="${1:-""}"
  echo -e "\\033[1;37m==> ${message}\\033[0m"
}

kubedee::log_success() {
  local -r message="${1:-""}"
  echo -e "\\033[1;32m==> ${message}\\033[0m"
}

kubedee::log_warn() {
  local -r message="${1:-""}"
  echo -e "\\033[1;33m==> ${message}\\033[0m" >&2
}

kubedee::log_error() {
  local -r message="${1:-""}"
  echo -e "\\033[1;31m==> ${message}\\033[0m" >&2
}

kubedee::exit_error() {
  local -r message="${1:-""}"
  local -r code="${2:-1}"
  kubedee::log_error "${message}"
  exit "${code}"
}

# shellcheck disable=SC2154
[[ -z "${kubedee_dir}" ]] && {
  kubedee::log_error "Internal error: \$kubedee_dir not set"
  return 1
}
# shellcheck disable=SC2154
[[ -z "${kubedee_version}" ]] && {
  kubedee::log_error "Internal error: \$kubedee_version not set"
  return 1
}
# shellcheck disable=SC2154
[[ -z "${kubedee_source_dir}" ]] && {
  kubedee::log_error "Internal error: \$kubedee_source_dir not set"
  return 1
}

readonly kubedee_base_image="ubuntu:20.04"
readonly kubedee_etcd_version="v3.4.14"
readonly kubedee_runc_version="v1.0.0-rc93"
readonly kubedee_cni_plugins_version="v0.9.1"
readonly kubedee_crio_version="v1.20.0"
readonly kubedee_go_version="1.15.8"
readonly kubedee_conmon_version="v2.0.26"

readonly lxd_status_code_running=103

readonly lxc_driver_version="$(lxc info | awk '/[:space:]*driver_version/ {print $2}')"
if [[ "${lxc_driver_version}" == 2* ]]; then
  readonly raw_lxc_apparmor_profile="lxc.aa_profile=unconfined"
  readonly raw_lxc_apparmor_allow_incomplete="lxc.aa_allow_incomplete=1"
else
  readonly raw_lxc_apparmor_profile="lxc.apparmor.profile=unconfined"
  readonly raw_lxc_apparmor_allow_incomplete="lxc.apparmor.allow_incomplete=1"
fi

# Args:
#   $1 The full container name
kubedee::fixup_network_ifaces() {
  local -r container_name="${1}" iface_src="enp5s0" iface_dest="eth0"

  # shellcheck disable=SC2016
  until lxc exec "${container_name}" -- bash -c 'sed -i "s/\(^[[:space:]]*linux.*\)/\1 net.ifnames=0/g" $(find /boot -iname grub.cfg)' &>/dev/null; do
    sleep 3
  done
  lxc exec "${container_name}" -- bash -c "sed -i 's/${iface_src}/${iface_dest}/g' /etc/netplan/*"
  lxc restart "${container_name}"
  until lxc exec "${container_name}" -- bash -c '[ ! -e /run/nologin ]' &>/dev/null; do
    sleep 3
  done
}

# Args:
#   $1 The full container name
kubedee::ensure_machine_id() {
  local -r container_name="${1}"
  until lxc exec "${container_name}" -- bash -c 'rm /etc/machine-id; dbus-uuidgen --ensure=/etc/machine-id'; do
    sleep 3
  done
  lxc restart "${container_name}"
  until lxc exec "${container_name}" -- bash -c '[ ! -e /run/nologin ]' &>/dev/null; do
    sleep 3
  done
}

# Args:
#   $1 The unvalidated cluster name
#
# Return validated name or exit with error
kubedee::validate_name() {
  local -r orig_name="${1:-}"
  # We must be fairly strict about names, since they are used
  # for container's hostname
  if ! echo "${orig_name}" | grep -qE '^[[:alnum:]_.-]{1,50}$'; then
    kubedee::exit_error "Invalid name (only '[[:alnum:]-]{1,50}' allowed): ${orig_name}"
  fi
  # Do some normalization to allow input like 'v1.8.4' while
  # matching host name requirements
  local -r name="${orig_name//[._]/-}"
  if [[ "${orig_name}" != "${name}" ]]; then
    kubedee::log_warn "Normalized name '${orig_name}' -> '${name}'"
  fi
  echo "${name}"
}

# Args:
#   $1 The target directory
kubedee::cd_or_exit_error() {
  local -r target="${1}"
  cd "${target}" || kubedee::exit_error "Failed to cd to ${target}"
}

# Args:
#   $1 The validated cluster name
kubedee::create_network() {
  local -r cluster_name="${1}"
  mkdir -p "${kubedee_dir}/clusters/${cluster_name}"
  local -r network_id_file="${kubedee_dir}/clusters/${cluster_name}/network_id"
  local network_id
  if [[ -e "${network_id_file}" ]]; then
    network_id="$(cat "${network_id_file}")"
  else
    network_id="$(tr -cd 'a-z0-9' </dev/urandom | head -c 6 || true)"
    echo "kubedee-${network_id}" >"${network_id_file}"
  fi
  if ! lxc network show "kubedee-${network_id}" &>/dev/null; then
    kubedee::log_info "Creating network for ${cluster_name} ..."
    lxc network create "kubedee-${network_id}"
  fi
}

# Args:
#   $1 The validated cluster name
kubedee::delete_network() {
  local -r cluster_name="${1}"
  local -r network_id_file="${kubedee_dir}/clusters/${cluster_name}/network_id"
  kubedee::log_info "Deleting network for ${cluster_name} ..."
  [[ -f "${network_id_file}" ]] || {
    kubedee::log_warn "${network_id_file} doesn't exist"
    return
  }
  local network_id
  network_id="$(cat "${network_id_file}")"
  if lxc network show "${network_id}" &>/dev/null; then
    lxc network delete "${network_id}"
  fi
  rm -f "${network_id_file}"
}

# Args:
#   $1 The storage pool name (optional)
#   $2 The storage pool driver (optional)
kubedee::create_storage_pool() {
  local -r cluster_name="${1:-kubedee}"
  local -r driver="${2:-btrfs}"
  if ! lxc storage show "${cluster_name}" &>/dev/null; then
    kubedee::log_info "Creating new storage pool for kubedee ..."
    lxc storage create "${cluster_name}" "${driver}"
  fi
}

# Args:
#   $1 The full container name
kubedee::container_status_code() {
  local -r container_name="${1}"
  lxc list --format json | jq -r ".[] | select(.name == \"${container_name}\").state.status_code"
}

# Args:
#   $1 The full container name
kubedee::container_ipv4_address() {
  local -r container_name="${1}"
  lxc list --format json | jq -r ".[] | select(.name == \"${container_name}\").state.network | to_entries[] | select(.value.type == \"broadcast\").value.addresses[] | select(.family == \"inet\").address" | head -n1
}

# Args:
#   $1 The full container name
kubedee::container_type() {
  local -r container_name="${1}"
  lxc list --format json | jq -r ".[] | select(.name == \"${container_name}\").type"
}

# Args:
#   $1 The full container name
kubedee::container_wait_running() {
  local -r cluster_name="${1}"
  until [[ "$(kubedee::container_status_code "${cluster_name}")" -eq ${lxd_status_code_running} ]]; do
    kubedee::log_info "Waiting for ${cluster_name} to reach state running ..."
    sleep 3
  done
  until [[ "$(kubedee::container_ipv4_address "${cluster_name}")" != "" ]]; do
    kubedee::log_info "Waiting for ${cluster_name} to get IPv4 address ..."
    sleep 3
  done
  if [[ "$(kubedee::container_type "${cluster_name}")" == "container" ]]; then
    lxc config device set "${cluster_name}" eth0 ipv4.address "$(kubedee::container_ipv4_address "${cluster_name}")"
  fi
  until [[ "$(kubedee::container_ipv4_address "${cluster_name}")" != "" ]]; do
    kubedee::log_info "Waiting for ${cluster_name} to settle it's assigned IPv4 address ..."
    sleep 3
  done
}

# Args:
#   $1 The validated cluster name
kubedee::create_certificate_authority_k8s() {
  local -r cluster_name="${1}"
  local -r target_dir="${kubedee_dir}/clusters/${cluster_name}/certificates"
  mkdir -p "${target_dir}"
  (
    kubedee::cd_or_exit_error "${target_dir}"
    kubedee::log_info "Generating certificate authority for Kubernetes ..."
    cat <<EOF | cfssl gencert -initca - | cfssljson -bare ca
{
  "CN": "Kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "DE",
      "L": "Berlin",
      "O": "Kubernetes",
      "OU": "CA",
      "ST": "Berlin"
    }
  ]
}
EOF
    cat >ca-config.json <<EOF
{
  "signing": {
    "default": {
      "expiry": "8760h"
    },
    "profiles": {
      "kubernetes": {
        "usages": ["signing", "key encipherment", "server auth", "client auth"],
        "expiry": "8760h"
      }
    }
  }
}
EOF
  )
}

# Args:
#   $1 The validated cluster name
kubedee::create_certificate_authority_aggregation() {
  local -r cluster_name="${1}"
  local -r target_dir="${kubedee_dir}/clusters/${cluster_name}/certificates"
  mkdir -p "${target_dir}"
  (
    kubedee::cd_or_exit_error "${target_dir}"
    kubedee::log_info "Generating certificate authority for Kubernetes Front Proxy ..."
    cat <<EOF | cfssl gencert -initca - | cfssljson -bare ca-aggregation
{
  "CN": "Kubernetes Front Proxy CA",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "DE",
      "L": "Berlin",
      "O": "Kubernetes Front Proxy",
      "OU": "CA",
      "ST": "Berlin"
    }
  ]
}
EOF
  )
}

# Args:
#   $1 The validated cluster name
kubedee::create_certificate_authority_etcd() {
  local -r cluster_name="${1}"
  local -r target_dir="${kubedee_dir}/clusters/${cluster_name}/certificates"
  mkdir -p "${target_dir}"
  (
    kubedee::cd_or_exit_error "${target_dir}"
    kubedee::log_info "Generating certificate authority for etcd ..."
    cat <<EOF | cfssl gencert -initca - | cfssljson -bare ca-etcd
{
  "CN": "etcd",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "DE",
      "L": "Berlin",
      "O": "etcd",
      "OU": "CA",
      "ST": "Berlin"
    }
  ]
}
EOF
  )
}

# Args:
#   $1 The validated cluster name
kubedee::create_certificate_admin() {
  local -r cluster_name="${1}"
  local -r target_dir="${kubedee_dir}/clusters/${cluster_name}/certificates"
  mkdir -p "${target_dir}"
  (
    kubedee::cd_or_exit_error "${target_dir}"
    kubedee::log_info "Generating admin certificate ..."
    cat <<EOF | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes - | cfssljson -bare admin
{
  "CN": "admin",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "DE",
      "L": "Berlin",
      "O": "system:masters",
      "OU": "kubedee",
      "ST": "Berlin"
    }
  ]
}
EOF
  )
}

# Args:
#   $1 The validated cluster name
kubedee::create_certificate_aggregation_client() {
  local -r cluster_name="${1}"
  local -r target_dir="${kubedee_dir}/clusters/${cluster_name}/certificates"
  mkdir -p "${target_dir}"
  (
    kubedee::cd_or_exit_error "${target_dir}"
    kubedee::log_info "Generating aggregation client certificate ..."
    cat <<EOF | cfssl gencert -ca=ca-aggregation.pem -ca-key=ca-aggregation-key.pem -config=ca-config.json -profile=kubernetes - | cfssljson -bare aggregation-client
{
  "CN": "kube-apiserver",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "DE",
      "L": "Berlin",
      "O": "kube-apiserver",
      "OU": "kubedee",
      "ST": "Berlin"
    }
  ]
}
EOF
  )
}

# Args:
#   $1 The validated cluster name
kubedee::create_certificate_etcd() {
  local -r cluster_name="${1}"
  local -r target_dir="${kubedee_dir}/clusters/${cluster_name}/certificates"
  local ip
  ip="$(kubedee::container_ipv4_address "kubedee-${cluster_name}-etcd")"
  [[ -z "${ip}" ]] && kubedee::exit_error "Failed to get IPv4 for kubedee-${cluster_name}-etcd"
  mkdir -p "${target_dir}"
  (
    kubedee::cd_or_exit_error "${target_dir}"
    kubedee::log_info "Generating etcd certificate ..."
    cat <<EOF | cfssl gencert -ca=ca-etcd.pem -ca-key=ca-etcd-key.pem -config=ca-config.json -profile=kubernetes -hostname="${ip},127.0.0.1" - | cfssljson -bare etcd
{
  "CN": "etcd",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "DE",
      "L": "Berlin",
      "O": "etcd",
      "OU": "kubedee",
      "ST": "Berlin"
    }
  ]
}
EOF
  )
}

# Args:
#   $1 The validated cluster name
#   $2 Additional X509v3 Subject Alternative Name to set, comma separated (optional)
kubedee::create_certificate_kubernetes() {
  local -r cluster_name="${1}"
  local apiserver_extra_hostnames="${2:-}"
  [[ -n "${apiserver_extra_hostnames}" ]] && apiserver_extra_hostnames="${apiserver_extra_hostnames/#/,}"
  local -r target_dir="${kubedee_dir}/clusters/${cluster_name}/certificates"
  local -r container_name="kubedee-${cluster_name}-controller"
  kubedee::container_wait_running "${container_name}"
  local ip
  ip="$(kubedee::container_ipv4_address "kubedee-${cluster_name}-controller")"
  [[ -z "${ip}" ]] && kubedee::exit_error "Failed to get IPv4 for kubedee-${cluster_name}-controller"
  mkdir -p "${target_dir}"
  (
    kubedee::cd_or_exit_error "${target_dir}"
    kubedee::log_info "Generating controller certificate ..."
    cat <<EOF | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes -hostname="10.32.0.1,${ip},127.0.0.1${apiserver_extra_hostnames}" - | cfssljson -bare kubernetes
{
  "CN": "kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "DE",
      "L": "Berlin",
      "O": "Kubernetes",
      "OU": "kubedee",
      "ST": "Berlin"
    }
  ]
}
EOF
    cat <<EOF | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes - | cfssljson -bare kube-proxy
{
  "CN": "system:kube-proxy",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "DE",
      "L": "Berlin",
      "O": "system:node-proxier",
      "OU": "kubedee",
      "ST": "Berlin"
    }
  ]
}
EOF
  )
}

# Args:
#   $1 The validated cluster name
#   $2 The container name
kubedee::create_certificate_worker() {
  local -r cluster_name="${1}"
  local -r container_name="${2}"
  local -r target_dir="${kubedee_dir}/clusters/${cluster_name}/certificates"
  local ip
  ip="$(kubedee::container_ipv4_address "${container_name}")"
  [[ -z "${ip}" ]] && kubedee::exit_error "Failed to get IPv4 for ${container_name}"
  mkdir -p "${target_dir}"
  (
    kubedee::cd_or_exit_error "${target_dir}"
    kubedee::log_info "Generating ${container_name} certificate ..."
    cat <<EOF | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes -hostname="${ip},${container_name}" - | cfssljson -bare "${container_name}"
{
  "CN": "system:node:${container_name}",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "DE",
      "L": "Berlin",
      "O": "system:nodes",
      "OU": "kubedee",
      "ST": "Berlin"
    }
  ]
}
EOF
  )
}

# Args:
#   $1 The validated cluster name
kubedee::create_certificate_kube_controller_manager() {
  local -r cluster_name="${1}"
  local -r target_dir="${kubedee_dir}/clusters/${cluster_name}/certificates"
  mkdir -p "${target_dir}"
  (
    kubedee::cd_or_exit_error "${target_dir}"
    kubedee::log_info "Generating kube-controller-manager certificate ..."
    cat <<EOF | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes - | cfssljson -bare kube-controller-manager
{
  "CN": "system:kube-controller-manager",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "DE",
      "L": "Berlin",
      "O": "system:kube-controller-manager",
      "OU": "kubedee",
      "ST": "Berlin"
    }
  ]
}
EOF
  )
}

# Args:
#   $1 The validated cluster name
kubedee::create_certificate_kube_scheduler() {
  local -r cluster_name="${1}"
  local -r target_dir="${kubedee_dir}/clusters/${cluster_name}/certificates"
  mkdir -p "${target_dir}"
  (
    kubedee::cd_or_exit_error "${target_dir}"
    kubedee::log_info "Generating kube-scheduler certificate ..."
    cat <<EOF | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes - | cfssljson -bare kube-scheduler
{
  "CN": "system:kube-scheduler",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "DE",
      "L": "Berlin",
      "O": "system:kube-scheduler",
      "OU": "kubedee",
      "ST": "Berlin"
    }
  ]
}
EOF
  )
}

# Args:
#   $1 The validated cluster name
kubedee::create_kubeconfig_admin() {
  local -r cluster_name="${1}"
  local -r cluster_dir="${kubedee_dir}/clusters/${cluster_name}"
  local controller_ip
  controller_ip="$(kubedee::container_ipv4_address "kubedee-${cluster_name}-controller")"
  mkdir -p "${cluster_dir}/kubeconfig"

  kubectl config set-cluster kubedee \
    --certificate-authority="${cluster_dir}/certificates/ca.pem" \
    --embed-certs=true \
    --server="https://${controller_ip}:6443" \
    --kubeconfig="${cluster_dir}/kubeconfig/admin.kubeconfig"

  kubectl config set-credentials admin \
    --client-certificate="${cluster_dir}/certificates/admin.pem" \
    --client-key="${cluster_dir}/certificates/admin-key.pem" \
    --embed-certs=true \
    --kubeconfig="${cluster_dir}/kubeconfig/admin.kubeconfig"

  kubectl config set-context default \
    --cluster=kubedee \
    --user=admin \
    --kubeconfig="${cluster_dir}/kubeconfig/admin.kubeconfig"

  kubectl config use-context default --kubeconfig="${cluster_dir}/kubeconfig/admin.kubeconfig"
}

# Args:
#   $1 The validated cluster name
kubedee::create_kubeconfig_controller() {
  local -r cluster_name="${1}"
  local -r cluster_dir="${kubedee_dir}/clusters/${cluster_name}"
  local controller_ip
  controller_ip="$(kubedee::container_ipv4_address "kubedee-${cluster_name}-controller")"
  mkdir -p "${cluster_dir}/kubeconfig"

  kubedee::log_info "Generating ${container_name} kubeconfig ..."

  kubectl config set-cluster kubedee \
    --certificate-authority="${cluster_dir}/certificates/ca.pem" \
    --embed-certs=true \
    --server="https://${controller_ip}:6443" \
    --kubeconfig="${cluster_dir}/kubeconfig/kube-controller-manager.kubeconfig"

  kubectl config set-credentials kube-controller-manager \
    --client-certificate="${cluster_dir}/certificates/kube-controller-manager.pem" \
    --client-key="${cluster_dir}/certificates/kube-controller-manager-key.pem" \
    --embed-certs=true \
    --kubeconfig="${cluster_dir}/kubeconfig/kube-controller-manager.kubeconfig"

  kubectl config set-context default \
    --cluster=kubedee \
    --user=kube-controller-manager \
    --kubeconfig="${cluster_dir}/kubeconfig/kube-controller-manager.kubeconfig"

  kubectl config use-context default --kubeconfig="${cluster_dir}/kubeconfig/kube-controller-manager.kubeconfig"

  kubectl config set-cluster kubedee \
    --certificate-authority="${cluster_dir}/certificates/ca.pem" \
    --embed-certs=true \
    --server="https://${controller_ip}:6443" \
    --kubeconfig="${cluster_dir}/kubeconfig/kube-scheduler.kubeconfig"

  kubectl config set-credentials kube-scheduler \
    --client-certificate="${cluster_dir}/certificates/kube-scheduler.pem" \
    --client-key="${cluster_dir}/certificates/kube-scheduler-key.pem" \
    --embed-certs=true \
    --kubeconfig="${cluster_dir}/kubeconfig/kube-scheduler.kubeconfig"

  kubectl config set-context default \
    --cluster=kubedee \
    --user=kube-scheduler \
    --kubeconfig="${cluster_dir}/kubeconfig/kube-scheduler.kubeconfig"

  kubectl config use-context default --kubeconfig="${cluster_dir}/kubeconfig/kube-scheduler.kubeconfig"
}

# Args:
#   $1 The validated cluster name
#   $2 The container name
kubedee::create_kubeconfig_worker() {
  local -r cluster_name="${1}"
  local -r container_name="${2}"
  local -r cluster_dir="${kubedee_dir}/clusters/${cluster_name}"
  local controller_ip
  controller_ip="$(kubedee::container_ipv4_address "kubedee-${cluster_name}-controller")"
  mkdir -p "${cluster_dir}/kubeconfig"

  kubedee::log_info "Generating ${container_name} kubeconfig ..."

  kubectl config set-cluster kubedee \
    --certificate-authority="${cluster_dir}/certificates/ca.pem" \
    --embed-certs=true \
    --server="https://${controller_ip}:6443" \
    --kubeconfig="${cluster_dir}/kubeconfig/kube-proxy.kubeconfig"

  kubectl config set-credentials kube-proxy \
    --client-certificate="${cluster_dir}/certificates/kube-proxy.pem" \
    --client-key="${cluster_dir}/certificates/kube-proxy-key.pem" \
    --embed-certs=true \
    --kubeconfig="${cluster_dir}/kubeconfig/kube-proxy.kubeconfig"

  kubectl config set-context default \
    --cluster=kubedee \
    --user=kube-proxy \
    --kubeconfig="${cluster_dir}/kubeconfig/kube-proxy.kubeconfig"

  kubectl config use-context default --kubeconfig="${cluster_dir}/kubeconfig/kube-proxy.kubeconfig"

  kubectl config set-cluster kubedee \
    --certificate-authority="${cluster_dir}/certificates/ca.pem" \
    --embed-certs=true \
    --server="https://${controller_ip}:6443" \
    --kubeconfig="${cluster_dir}/kubeconfig/${container_name}-kubelet.kubeconfig"

  kubectl config set-credentials "system:node:${container_name}" \
    --client-certificate="${cluster_dir}/certificates/${container_name}.pem" \
    --client-key="${cluster_dir}/certificates/${container_name}-key.pem" \
    --embed-certs=true \
    --kubeconfig="${cluster_dir}/kubeconfig/${container_name}-kubelet.kubeconfig"

  kubectl config set-context default \
    --cluster=kubedee \
    --user="system:node:${container_name}" \
    --kubeconfig="${cluster_dir}/kubeconfig/${container_name}-kubelet.kubeconfig"

  kubectl config use-context default --kubeconfig="${cluster_dir}/kubeconfig/${container_name}-kubelet.kubeconfig"
}

# Args:
#   $1 The validated cluster name
kubedee::launch_etcd() {
  local -r cluster_name="${1}"
  local -r container_name="kubedee-${cluster_name}-etcd"
  local -r network_id_file="${kubedee_dir}/clusters/${cluster_name}/network_id"
  local network_id
  network_id="$(cat "${network_id_file}")"
  lxc info "${container_name}" &>/dev/null && return
  # shellcheck disable=SC2086,SC2154
  lxc init --storage "${storage_pool}" \
    --config raw.lxc="${raw_lxc_apparmor_allow_incomplete}" \
    "${kubedee_container_image}" "${container_name}"
  lxc network attach "${network_id}" "${container_name}" eth0 eth0
  lxc start "${container_name}"
  kubedee::ensure_machine_id "${container_name}"
}

# Args:
#   $1 The validated cluster name
kubedee::configure_etcd() {
  local -r cluster_name="${1}"
  local -r container_name="kubedee-${cluster_name}-etcd"
  kubedee::container_wait_running "${container_name}"
  kubedee::create_certificate_etcd "${cluster_name}"
  local ip
  ip="$(kubedee::container_ipv4_address "${container_name}")"
  kubedee::log_info "Providing files to ${container_name} ..."

  lxc file push -p "${kubedee_dir}/clusters/${cluster_name}/certificates/"{etcd.pem,etcd-key.pem,ca-etcd.pem} "${container_name}/etc/etcd/"

  kubedee::log_info "Configuring ${container_name} ..."
  cat <<EOF | lxc exec "${container_name}" bash
set -euo pipefail
cat >/etc/systemd/system/etcd.service <<'ETCD_UNIT'
[Unit]
Description=etcd

[Service]
ExecStart=/usr/local/bin/etcd \\
  --name ${container_name} \\
  --cert-file=/etc/etcd/etcd.pem \\
  --key-file=/etc/etcd/etcd-key.pem \\
  --peer-cert-file=/etc/etcd/etcd.pem \\
  --peer-key-file=/etc/etcd/etcd-key.pem \\
  --trusted-ca-file=/etc/etcd/ca-etcd.pem \\
  --peer-trusted-ca-file=/etc/etcd/ca-etcd.pem \\
  --peer-client-cert-auth \\
  --client-cert-auth \\
  --initial-advertise-peer-urls https://${ip}:2380 \\
  --listen-peer-urls https://${ip}:2380 \\
  --listen-client-urls https://${ip}:2379,http://127.0.0.1:2379 \\
  --advertise-client-urls https://${ip}:2379 \\
  --initial-cluster-token etcd-cluster-0 \\
  --initial-cluster ${container_name}=https://${ip}:2380 \\
  --initial-cluster-state new \\
  --data-dir=/var/lib/etcd
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
ETCD_UNIT

systemctl daemon-reload
systemctl -q enable etcd
systemctl start etcd
EOF
}

# Args:
#   $1 The validated cluster name
kubedee::configure_controller() {
  local -r cluster_name="${1}"
  local -r container_name="${2}"
  local -r admission_plugins="${3}"
  local etcd_ip
  etcd_ip="$(kubedee::container_ipv4_address "kubedee-${cluster_name}-etcd")"
  kubedee::create_certificate_kube_controller_manager "${cluster_name}"
  kubedee::create_certificate_kube_scheduler "${cluster_name}"
  kubedee::create_kubeconfig_controller "${cluster_name}" "${container_name}"
  kubedee::container_wait_running "${container_name}"
  kubedee::log_info "Providing files to ${container_name} ..."

  lxc file push -p "${kubedee_dir}/clusters/${cluster_name}/certificates/"{kubernetes.pem,kubernetes-key.pem,ca.pem,ca-key.pem,etcd.pem,etcd-key.pem,ca-etcd.pem,ca-aggregation.pem,aggregation-client.pem,aggregation-client-key.pem} "${container_name}/etc/kubernetes/"

  lxc file push -p "${kubedee_dir}/clusters/${cluster_name}/kubeconfig/"{kube-controller-manager.kubeconfig,kube-scheduler.kubeconfig} "${container_name}/etc/kubernetes/"

  local kubescheduler_config_api_version="kubescheduler.config.k8s.io/v1beta1"
  local -r k8s_minor_version="$(lxc exec "${container_name}" -- /usr/local/bin/kubectl version --client -o json | jq -r .clientVersion.minor)"
  if [[ "${k8s_minor_version}" == 16* ]] ||
    [[ "${k8s_minor_version}" == 17* ]]; then
    kubescheduler_config_api_version="kubescheduler.config.k8s.io/v1alpha1"
  fi
  if [[ "${k8s_minor_version}" == 18* ]]; then
    kubescheduler_config_api_version="kubescheduler.config.k8s.io/v1alpha2"
  fi

  kubedee::log_info "Configuring ${container_name} ..."
  cat <<EOF | lxc exec "${container_name}" bash
set -euo pipefail
cat >/etc/systemd/system/kube-apiserver.service <<'KUBE_APISERVER_UNIT'
[Unit]
Description=Kubernetes API Server

[Service]
ExecStart=/usr/local/bin/kube-apiserver \\
  --allow-privileged=true \\
  --apiserver-count=3 \\
  --audit-log-maxage=30 \\
  --audit-log-maxbackup=3 \\
  --audit-log-maxsize=100 \\
  --audit-log-path=/var/log/audit.log \\
  --authorization-mode=Node,RBAC \\
  --bind-address=0.0.0.0 \\
  --client-ca-file=/etc/kubernetes/ca.pem \\
  --enable-admission-plugins=${admission_plugins} \\
  --enable-swagger-ui=true \\
  --etcd-cafile=/etc/kubernetes/ca-etcd.pem \\
  --etcd-certfile=/etc/kubernetes/etcd.pem \\
  --etcd-keyfile=/etc/kubernetes/etcd-key.pem \\
  --etcd-servers=https://${etcd_ip}:2379 \\
  --event-ttl=1h \\
  --kubelet-certificate-authority=/etc/kubernetes/ca.pem \\
  --kubelet-client-certificate=/etc/kubernetes/kubernetes.pem \\
  --kubelet-client-key=/etc/kubernetes/kubernetes-key.pem \\
  --kubelet-https=true \\
  --runtime-config=rbac.authorization.k8s.io/v1alpha1 \\
  --service-account-issuer=https://api \\
  --service-account-signing-key-file=/etc/kubernetes/ca-key.pem \\
  --service-account-api-audiences=kubernetes.default.svc \\
  --service-account-key-file=/etc/kubernetes/ca-key.pem \\
  --service-cluster-ip-range=10.32.0.0/24 \\
  --service-node-port-range=30000-32767 \\
  --tls-cert-file=/etc/kubernetes/kubernetes.pem \\
  --tls-private-key-file=/etc/kubernetes/kubernetes-key.pem \\
  --proxy-client-cert-file=/etc/kubernetes/aggregation-client.pem \\
  --proxy-client-key-file=/etc/kubernetes/aggregation-client-key.pem \\
  --requestheader-client-ca-file=/etc/kubernetes/ca-aggregation.pem \\
  --requestheader-extra-headers-prefix=X-Remote-Extra- \\
  --requestheader-group-headers=X-Remote-Group \\
  --requestheader-username-headers=X-Remote-User \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
KUBE_APISERVER_UNIT

cat >/etc/systemd/system/kube-controller-manager.service <<'KUBE_CONTROLLER_MANAGER_UNIT'
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-controller-manager \\
  --allocate-node-cidrs=true \\
  --cluster-cidr=10.244.0.0/16 \\
  --cluster-name=kubernetes \\
  --cluster-signing-cert-file=/etc/kubernetes/ca.pem \\
  --cluster-signing-key-file=/etc/kubernetes/ca-key.pem \\
  --kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig \\
  --leader-elect=true \\
  --root-ca-file=/etc/kubernetes/ca.pem \\
  --service-account-private-key-file=/etc/kubernetes/ca-key.pem \\
  --service-cluster-ip-range=10.32.0.0/24 \\
  --use-service-account-credentials=true \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
KUBE_CONTROLLER_MANAGER_UNIT

mkdir -p /etc/kubernetes/config
cat >/etc/kubernetes/config/kube-scheduler.yaml <<'KUBE_SCHEDULER_CONFIG'
apiVersion: ${kubescheduler_config_api_version}
kind: KubeSchedulerConfiguration
clientConnection:
  kubeconfig: "/etc/kubernetes/kube-scheduler.kubeconfig"
leaderElection:
  leaderElect: true
KUBE_SCHEDULER_CONFIG

cat >/etc/systemd/system/kube-scheduler.service <<'KUBE_SCHEDULER_UNIT'
[Unit]
Description=Kubernetes Scheduler

[Service]
ExecStart=/usr/local/bin/kube-scheduler \\
  --config=/etc/kubernetes/config/kube-scheduler.yaml \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
KUBE_SCHEDULER_UNIT

systemctl daemon-reload

systemctl -q enable kube-apiserver
systemctl start kube-apiserver

systemctl -q enable kube-controller-manager
systemctl start kube-controller-manager

systemctl -q enable kube-scheduler
systemctl start kube-scheduler
EOF

  kubedee::configure_worker "${cluster_name}" "${container_name}"
}

# Args:
#   $1 The validated cluster name
kubedee::apiserver_wait_running() {
  local -r cluster_name="${1}"
  local -r container_name="kubedee-${cluster_name}-controller"
  local -r cluster_certificates="${kubedee_dir}/clusters/${cluster_name}/certificates"

  kubedee::container_wait_running "${container_name}"
  until curl --ipv4 --fail --silent --max-time 3 \
    --cacert "${cluster_certificates}/ca.pem" \
    --key "${cluster_certificates}/admin-key.pem" \
    --cert "${cluster_certificates}/admin.pem" \
    "https://$(kubedee::container_ipv4_address "${container_name}"):6443/api" &>/dev/null; do
      kubedee::log_info "Waiting for kube-apiserver to become ready ..."
      sleep 3
  done
}

# Args:
#   $1 The validated cluster name
kubedee::configure_rbac() {
  local -r cluster_name="${1}"
  local -r container_name="kubedee-${cluster_name}-controller"
  local -r kubeconfig="${kubedee_dir}/clusters/${cluster_name}/kubeconfig/admin.kubeconfig"
  kubedee::apiserver_wait_running "${cluster_name}"
  kubedee::log_info "Configuring RBAC for kube-apiserver -> kubelet requests"

  # During apiserver initialization, resources are not available
  # immediately. Wait for 'clusterroles' to avoid the following:
  # error: unable to recognize "STDIN": no matches for kind "ClusterRole" in version "rbac.authorization.k8s.io/v1beta1"
  until kubectl --kubeconfig "${kubeconfig}" get clusterroles &>/dev/null; do sleep 1; done

  cat <<APISERVER_RBAC | kubectl --kubeconfig "${kubeconfig}" apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:kube-apiserver-to-kubelet
rules:
  - apiGroups:
      - ""
    resources:
      - nodes/proxy
      - nodes/stats
      - nodes/log
      - nodes/spec
      - nodes/metrics
    verbs:
      - "*"
APISERVER_RBAC

  cat <<APISERVER_BINDING | kubectl --kubeconfig "${kubeconfig}" apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:kube-apiserver
  namespace: ""
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:kube-apiserver-to-kubelet
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: kubernetes
APISERVER_BINDING
}

# Args:
#   $1 The validated cluster name
#   $2 The container name
kubedee::launch_container() {
  local -r cluster_name="${1}" container_name="${2}" container_cpu="${3:-$(nproc)}" container_memory="${4:-4GiB}"
  lxc info "${container_name}" &>/dev/null && return
  local -r network_id_file="${kubedee_dir}/clusters/${cluster_name}/network_id"
  local network_id
  network_id="$(cat "${network_id_file}")"
  read -r -d '' raw_lxc <<RAW_LXC || true
${raw_lxc_apparmor_profile}
lxc.mount.auto=proc:rw sys:rw cgroup:rw
lxc.cgroup.devices.allow=a
lxc.cap.drop=
${raw_lxc_apparmor_allow_incomplete}
RAW_LXC
  # shellcheck disable=SC2086,SC2154
  lxc init ${lxc_init_opts} \
    --profile default \
    --config limits.cpu=${container_cpu} \
    --config limits.memory=${container_memory} \
    --config security.privileged=true \
    --config security.nesting=true \
    --config linux.kernel_modules=ip_tables,ip6_tables,netlink_diag,nf_nat,overlay \
    --config raw.lxc="${raw_lxc}" \
    "${kubedee_image}" "${container_name}"
  lxc network attach "${network_id}" "${container_name}" eth0 eth0
  lxc start "${container_name}"
  kubedee::ensure_machine_id "${container_name}"
  until [ -n "$(kubedee::container_ipv4_address "${container_name}")" ]; do
    sleep 3
  done
}

# Args:
#   $1 The validated cluster name
#   $2 The container name
kubedee::configure_worker() {
  local -r cluster_name="${1}"
  local -r container_name="${2}"
  kubedee::container_wait_running "${container_name}"
  kubedee::create_certificate_worker "${cluster_name}" "${container_name}"
  kubedee::create_kubeconfig_worker "${cluster_name}" "${container_name}"
  kubedee::log_info "Providing files to ${container_name} ..."

  lxc file push -pr \
    "${kubedee_source_dir}/configs/crio/crictl.yaml" \
    "${kubedee_source_dir}/configs/crio/crio-umount.conf" \
    "${kubedee_source_dir}/configs/crio/policy.json" \
    "${kubedee_source_dir}/configs/crio/crio.conf" \
    "${container_name}/etc/crio"

  lxc file push -p "${kubedee_dir}/clusters/${cluster_name}/certificates/"{"${container_name}.pem","${container_name}-key.pem",ca.pem} "${container_name}/etc/kubernetes/"
  lxc file push -p "${kubedee_dir}/clusters/${cluster_name}/kubeconfig/"{"${container_name}-kubelet.kubeconfig",kube-proxy.kubeconfig} "${container_name}/etc/kubernetes/"

  if [[ "$(kubedee::container_type "${container_name}")" == "container" ]]; then
    # Mount the host loop devices into the container to allow the kubelet
    # to gather rootfs info when the host root is on a loop device
    # (e.g. `/dev/mapper/c--vg-root on /dev/loop1 type ext4 ...`)
    shopt -s nullglob
    for ldev in /dev/loop[0-9]*; do
      lxc config device add "${container_name}" "${ldev#/dev/}" unix-block source="${ldev}" path="${ldev}"
    done
    shopt -u nullglob

    # Mount the host /dev/kmsg device into the container to allow
    # kubelet's OOM manager to do its job. Otherwise we encounter the
    # following error:
    # `Failed to start OOM watcher open /dev/kmsg: no such file or directory`
    lxc config device add "${container_name}" "kmsg" unix-char source="/dev/kmsg" path="/dev/kmsg"
  fi

  kubedee::log_info "Configuring ${container_name} ..."
  cat <<EOF | lxc exec "${container_name}" bash
set -euo pipefail

mkdir -p /etc/containers
mkdir -p /usr/share/containers/oci/hooks.d

ln -s /etc/crio/policy.json /etc/containers/policy.json

mkdir -p /etc/cni/net.d

cat >/etc/systemd/system/crio.service <<'CRIO_UNIT'
[Unit]
Description=CRI-O daemon

[Service]
ExecStart=/usr/local/bin/crio --registry docker.io
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
CRIO_UNIT

mkdir -p /etc/kubernetes/config
cat >/etc/kubernetes/config/kubelet.yaml <<'KUBELET_CONFIG'
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
  x509:
    clientCAFile: "/etc/kubernetes/ca.pem"
authorization:
  mode: Webhook
clusterDomain: "cluster.local"
clusterDNS:
  - "10.32.0.10"
podCIDR: "10.20.0.0/16"
runtimeRequestTimeout: "10m"
tlsCertFile: "/etc/kubernetes/${container_name}.pem"
tlsPrivateKeyFile: "/etc/kubernetes/${container_name}-key.pem"
failSwapOn: false
evictionHard: {}
enforceNodeAllocatable: []

# TODO(schu): check if issues were updated
# https://github.com/kubernetes/kubernetes/issues/66067
# https://github.com/kubernetes-sigs/cri-o/issues/1769
resolverConfig: /run/systemd/resolve/resolv.conf
KUBELET_CONFIG

# Another hotfix attempt for the bug ^^^ as setting
# resolverConfig for the kubelet doesn't seem to work
# with cri-o
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

cat >/etc/systemd/system/kubelet.service <<'KUBELET_UNIT'
[Unit]
Description=Kubernetes Kubelet
After=crio.service
Requires=crio.service

[Service]
ExecStart=/usr/local/bin/kubelet \\
  --cgroup-driver=systemd \\
  --config=/etc/kubernetes/config/kubelet.yaml \\
  --container-runtime=remote \\
  --container-runtime-endpoint=unix:///var/run/crio/crio.sock \\
  --image-service-endpoint=unix:///var/run/crio/crio.sock \\
  --kubeconfig=/etc/kubernetes/${container_name}-kubelet.kubeconfig \\
  --network-plugin=cni \\
  --register-node=true \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
KUBELET_UNIT

cat >/etc/systemd/system/kube-proxy.service <<'KUBE_PROXY_UNIT'
[Unit]
Description=Kubernetes Kube Proxy

[Service]
ExecStart=/usr/local/bin/kube-proxy \\
  --cluster-cidr=10.200.0.0/16 \\
  --kubeconfig=/etc/kubernetes/kube-proxy.kubeconfig \\
  --proxy-mode=iptables \\
  --conntrack-max-per-core=0 \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
KUBE_PROXY_UNIT

systemctl daemon-reload

systemctl -q enable crio
systemctl start crio

systemctl -q enable kubelet
systemctl start kubelet

systemctl -q enable kube-proxy
systemctl start kube-proxy
EOF
}

# Args:
#   $1 The validated cluster name
kubedee::deploy_pod_security_policies() {
  local -r cluster_name="${1}"
  kubedee::log_info "Deploying default pod security policies ..."
  local -r psp_manifest="${kubedee_source_dir}/manifests/pod-security-policies.yml"
  kubectl --kubeconfig "${kubedee_dir}/clusters/${cluster_name}/kubeconfig/admin.kubeconfig" \
    apply -f "${psp_manifest}"
}

# Args:
#   $1 The validated cluster name
kubedee::deploy_flannel() {
  local -r cluster_name="${1}"
  kubedee::log_info "Deploying flannel ..."
  local -r flannel_manifest="${kubedee_source_dir}/manifests/kube-flannel.yml"
  kubectl --kubeconfig "${kubedee_dir}/clusters/${cluster_name}/kubeconfig/admin.kubeconfig" \
    apply -f "${flannel_manifest}"
}

# Args:
#   $1 The validated cluster name
kubedee::deploy_core_dns() {
  local -r cluster_name="${1}"
  kubedee::log_info "Deploying core-dns ..."
  local -r dns_manifest="${kubedee_source_dir}/manifests/core-dns.yml"
  kubectl --kubeconfig "${kubedee_dir}/clusters/${cluster_name}/kubeconfig/admin.kubeconfig" \
    apply -f "${dns_manifest}"
}

# Args:
#   $1 The validated cluster name
#   $2 The name of the controller node
kubedee::label_and_taint_controller() {
  local -r cluster_name="${1}"
  local -r controller_node_name="${2}"
  kubedee::log_info "Applying labels and taints to ${controller_node_name} ..."
  kubectl --kubeconfig "${kubedee_dir}/clusters/${cluster_name}/kubeconfig/admin.kubeconfig" \
    label node "${controller_node_name}" node-role.kubernetes.io/master=""
  kubectl --kubeconfig "${kubedee_dir}/clusters/${cluster_name}/kubeconfig/admin.kubeconfig" \
    label node "${controller_node_name}" ingress-nginx=""
  kubectl --kubeconfig "${kubedee_dir}/clusters/${cluster_name}/kubeconfig/admin.kubeconfig" \
    taint node "${controller_node_name}" node-role.kubernetes.io/master=:NoSchedule
}

# Args:
#   $1 The validated cluster name
#   $2 The name of the worker node
kubedee::label_worker() {
  local -r cluster_name="${1}"
  local -r node_name="${2}"
  kubedee::log_info "Applying labels to ${node_name} ..."
  kubectl --kubeconfig "${kubedee_dir}/clusters/${cluster_name}/kubeconfig/admin.kubeconfig" \
    label node "${node_name}" node-role.kubernetes.io/node=""
}

# Args:
#   $1 The validated cluster name
#   $2 The name of the worker node
kubedee::wait_for_node() {
  local -r cluster_name="${1}"
  local -r node_name="${2}"
  until kubectl --kubeconfig "${kubedee_dir}/clusters/${cluster_name}/kubeconfig/admin.kubeconfig" get node "${node_name}" &>/dev/null; do
    kubedee::log_info "Waiting for node ${node_name} to be registered ..."
    sleep 3
  done
}

# Args:
#   $1 The validated cluster name
#   $2 Image name
#   $3 Image type
kubedee::prepare_image() {
  local -r cluster_name="${1}" image_name="${2:-${kubedee_image}}" image_type="${3:-container}"
  local -r builder_instance="${image_name}-setup"
  lxc image info "${image_name}" &>/dev/null && return
  kubedee::log_info "Preparing kubedee ${image_type} image ..."
  lxc delete -f "${builder_instance}" &>/dev/null || true
  local -r network_id_file="${kubedee_dir}/clusters/${cluster_name}/network_id"
  local network_id
  network_id="$(cat "${network_id_file}")"
  # shellcheck disable=SC2086
  [[ "${image_type}" == "vm" ]] && prep_init_opts="${lxc_init_opts}" || prep_init_opts=""
  lxc init ${prep_init_opts} \
    --storage default \
    --config raw.lxc="${raw_lxc_apparmor_allow_incomplete}" \
    --config limits.memory=4GiB \
    "${kubedee_base_image}" "${builder_instance}"
  lxc config device set "${builder_instance}" root size="${rootfs_size:-10GiB}"
  lxc network attach "${network_id}" "${builder_instance}" eth0 eth0
  lxc start "${builder_instance}"
  kubedee::container_wait_running "${builder_instance}"

  # system dependencies
  cat <<EOF | lxc exec "${builder_instance}" -- bash
set -eo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update

# crio requires libgpgme11
# helm requires socat
apt-get install -y curl iptables libgpgme11 socat

## build dependencies
apt-get install -y --no-install-recommends \
  build-essential \
  libglib2.0-dev \
  libseccomp-dev \
  libsystemd-dev \
  make \
  pkg-config
curl -sSL 'https://dl.google.com/go/go${kubedee_go_version}.linux-amd64.tar.gz' | tar -xzC /usr/local
export GOCACHE=/tmp/go-cache GOPATH=/go PATH="\${PATH}:/usr/local/go/bin"

# cri-o
mkdir -p /go/src/github.com/cri-o/cri-o
cd /go/src/github.com/cri-o/cri-o
curl -sSL https://github.com/cri-o/cri-o/archive/${kubedee_crio_version}.tar.gz | tar --strip-components 1 -xzC /go/src/github.com/cri-o/cri-o
make clean
make
cp bin/* /usr/local/bin

# conmon
mkdir -p /go/src/github.com/containers/conmon
cd /go/src/github.com/containers/conmon
curl -sSL https://github.com/containers/conmon/archive/${kubedee_conmon_version}.tar.gz | tar --strip-components 1 -xzC /go/src/github.com/containers/conmon
make clean
make
cp bin/conmon /usr/local/bin

## cleanup
cd /tmp
apt-get remove -y --auto-remove \
  build-essential \
  libglib2.0-dev \
  libseccomp-dev \
  libsystemd-dev \
  make \
  pkg-config
rm -rf /go /usr/local/go

## fetch prebuilts
# etcd
curl -fsSL "https://github.com/coreos/etcd/releases/download/${kubedee_etcd_version}/etcd-${kubedee_etcd_version}-linux-amd64.tar.gz" | tar -xzC /usr/local/bin --strip-components 1 etcd-${kubedee_etcd_version}-linux-amd64/{etcdctl,etcd} ||:

# runc
curl -fsSL -o /usr/bin/runc "https://github.com/opencontainers/runc/releases/download/${kubedee_runc_version}/runc.amd64"
chmod +x /usr/bin/runc

# cni
mkdir -p /opt/cni/bin
curl -fsSL https://github.com/containernetworking/plugins/releases/download/${kubedee_cni_plugins_version}/cni-plugins-linux-amd64-${kubedee_cni_plugins_version}.tgz | tar -xzC /opt/cni/bin

# yank out snap
SNAPS=(\$(snap list | tail -n+2 | awk '{print \$1}')) ||:
until [ -z "\${SNAPS}" ]; do
  for i in \${SNAPS[@]}; do
    snap remove --purge \${i} ||:
  done
  SNAPS=(\$(snap list | tail -n+2 | awk '{print \$1}')) ||:
done
apt-get purge -y snapd ||:

# yank out cloud-init
apt-get purge -y \$(dpkg -l | awk '/^ii\s*cloud-/ {print \$2}') ||:
rm -rf /var/lib/cloud/

rm -rf /var/cache/apt /etc/machine-id /var/lib/systemd/random-seed
EOF

  # shellcheck disable=SC2154
  if [[ -n "${kubernetes_version}" ]]; then
    cat <<EOF | lxc exec "${builder_instance}" -- bash
cd /usr/local/bin
curl -fsSL -o- 'https://dl.k8s.io/${kubernetes_version}/kubernetes-server-linux-amd64.tar.gz' | \\
tar -xz --strip-components 3 kubernetes/server/bin/{kube-apiserver,kube-controller-manager,kubectl,kubelet,kube-proxy,kube-scheduler}
EOF
  else
    # shellcheck disable=SC2154
    lxc file push -pr \
      "${bin_dir}/kube-apiserver" \
      "${bin_dir}/kube-controller-manager" \
      "${bin_dir}/kubectl" \
      "${bin_dir}/kubelet" \
      "${bin_dir}/kube-proxy" \
      "${bin_dir}/kube-scheduler" \
      "${builder_instance}/usr/local/bin"
  fi

  if [[ "${image_type}" == "vm" ]]; then
    kubedee::fixup_network_ifaces "${builder_instance}"
  fi

  lxc stop "${builder_instance}"
  lxc snapshot "${builder_instance}" snap
  lxc publish "${builder_instance}/snap" --alias "${image_name}" kubedee-version="${kubedee_version}"
  lxc delete -f "${builder_instance}" || lxc network detach "${network_id}" "${builder_instance}"
}

# Args:
#   $1 The validated cluster name
kubedee::smoke_test() {
  local -r cluster_name="${1}"
  local -r kubeconfig="${kubedee_dir}/clusters/${cluster_name}/kubeconfig/admin.kubeconfig"
  local deployment_suffix
  deployment_suffix="$(tr -cd 'a-z0-9' </dev/urandom | head -c 6 || true)"
  local -r deployment_name="kubedee-smoke-test-${cluster_name}-${deployment_suffix}"
  kubedee::log_info "Running smoke test for cluster ${cluster_name} ..."
  kubectl --kubeconfig "${kubeconfig}" create deploy "${deployment_name}" --image=nginx
  kubectl --kubeconfig "${kubeconfig}" scale deploy "${deployment_name}" --replicas=3
  kubectl --kubeconfig "${kubeconfig}" expose deployment "${deployment_name}" --target-port=80 --port=8080 --type=NodePort
  # Pick one of the worker nodes with kube-proxy
  # running and test if the service is reachable
  local worker
  for c in $(lxc list --format json | jq -r '.[].name'); do
    if [[ "${c}" == "kubedee-${cluster_name}-worker-"* ]]; then
      worker="${c}"
      break
    fi
  done
  delete_smoke_test() {
    kubectl --kubeconfig "${kubeconfig}" delete service "${deployment_name}"
    kubectl --kubeconfig "${kubeconfig}" delete deployment "${deployment_name}"
  }
  if [[ -z "${worker}" ]]; then
    delete_smoke_test
    kubedee::exit_error "No worker node found in cluster ${cluster_name} to run smoke test"
  fi
  local worker_ip
  worker_ip="$(kubedee::container_ipv4_address "${worker}")"
  local service_port
  service_port="$(kubectl --kubeconfig "${kubeconfig}" get services "${deployment_name}" -o jsonpath='{.spec.ports[0].nodePort}')"
  local now
  now="$(date +%s)"
  local timeout
  timeout=$((now + 240))
  while true; do
    if [[ $(date +%s) -gt ${timeout} ]]; then
      delete_smoke_test
      kubedee::exit_error "Failed to connect to ${deployment_name} within 240 seconds"
    fi
    if curl --ipv4 --fail --silent --max-time 3 "${worker_ip}:${service_port}" | grep -q "Welcome to nginx!"; then
      break
    else
      kubedee::log_info "${deployment_name} not ready yet"
      sleep 5
    fi
  done
  kubedee::log_success "Successfully connected to ${deployment_name}"
  delete_smoke_test
}

# Args:
#   $1 The validated cluster name
kubedee::configure_kubeconfig() {
  local -r cluster_name="${1}"
  local -r cluster_context_name="kubedee-${cluster_name}"
  local -r cluster_creds_name="${cluster_context_name}-admin"
  local ip
  ip="$(kubedee::container_ipv4_address "kubedee-${cluster_name}-controller")"
  [[ -z "${ip}" ]] && kubedee::exit_error "Failed to get IPv4 for kubedee-${cluster_name}-controller"
  kubectl config set-cluster "${cluster_context_name}" \
    --certificate-authority="${kubedee_dir}/clusters/${cluster_name}/certificates/ca.pem" \
    --server="https://${ip}:6443"
  kubectl config set-credentials "${cluster_creds_name}" \
    --client-certificate="${kubedee_dir}/clusters/${cluster_name}/certificates/admin.pem" \
    --client-key="${kubedee_dir}/clusters/${cluster_name}/certificates/admin-key.pem"
  kubectl config set-context "${cluster_context_name}" \
    --cluster="${cluster_context_name}" \
    --user="${cluster_creds_name}"
  kubectl config use-context "${cluster_context_name}"
}

# Args:
#   $1 The validated cluster name
kubedee::create_admin_service_account() {
  local -r cluster_name="${1}"
  local -r kubeconfig="${kubedee_dir}/clusters/${cluster_name}/kubeconfig/admin.kubeconfig"
  local -r sa_manifest="${kubedee_source_dir}/manifests/service-account-admin.yml"
  kubedee::log_info "Adding 'kubedee-admin' service account ..."
  kubectl --kubeconfig "${kubedee_dir}/clusters/${cluster_name}/kubeconfig/admin.kubeconfig" \
    apply -f "${sa_manifest}"
}

# Args:
#   $1 The validated cluster name
kubedee::create_user_service_account() {
  local -r cluster_name="${1}"
  local -r kubeconfig="${kubedee_dir}/clusters/${cluster_name}/kubeconfig/admin.kubeconfig"
  local -r sa_manifest="${kubedee_source_dir}/manifests/service-account-user.yml"
  kubedee::log_info "Adding 'kubedee-user' service account ..."
  kubectl --kubeconfig "${kubedee_dir}/clusters/${cluster_name}/kubeconfig/admin.kubeconfig" \
    apply -f "${sa_manifest}"
}

# Args:
#   $1 The validated cluster name
kubedee::get_service_account_token() {
  local -r cluster_name="${1}"
  local -r name="${2}"
  local -r namespace="${3:-default}"
  local -r kubeconfig="${kubedee_dir}/clusters/${cluster_name}/kubeconfig/admin.kubeconfig"
  if ! kubectl --kubeconfig "${kubeconfig}" get serviceaccount -n "${namespace}" "${name}" &>/dev/null; then
    kubedee::exit_error "No service account with name '${name}' found in namespace '${namespace}'"
  fi
  local sa_secret
  sa_secret="$(kubectl --kubeconfig "${kubeconfig}" get serviceaccount -n "${namespace}" "${name}" -o jsonpath='{.secrets[0].name}')"
  local sa_token
  sa_token="$(kubectl --kubeconfig "${kubeconfig}" get secret -n "${namespace}" "${sa_secret}" -o jsonpath='{.data.token}')"
  echo "${sa_token}" | base64 -d
}
