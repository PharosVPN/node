#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 The PharosVPN Authors
#
# PharosVPN node node base prep (milestone B6), run as cloud-init user-data on a
# fresh Ubuntu 24.04 droplet. It installs the AmneziaWG data plane (kernel
# module + awg / awg-quick tools) and enables IP forwarding, so that `cox nodes
# add` can then install and enroll the node agent over SSH. coxswain still pushes
# the per-node network policy (decision 16); this only lays the data-plane base.
set -uxo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y software-properties-common curl ca-certificates

# AmneziaWG kernel module (DKMS) + userspace tools, from the official PPA.
add-apt-repository -y ppa:amnezia/ppa
apt-get update
apt-get install -y "linux-headers-$(uname -r)" amneziawg amneziawg-tools

# Data-plane forwarding (coxswain still owns masquerade/isolation/transit policy).
cat >/etc/sysctl.d/99-pharos.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
sysctl --system

# Load the module now so awg-quick works without waiting for a reboot.
modprobe amneziawg || true

# Marker the controller / our checks can look for.
if command -v awg >/dev/null 2>&1; then
  awg --version >/etc/pharos-node-prep.txt 2>&1 || true
  touch /var/lib/pharos-node-prepped
fi
