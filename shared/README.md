# PipeJack Deployment Kit — Shared Assets and Network Utilities

This directory contains shared configuration templates, network planning examples, and guest network bootstrapping utilities that are common across both nodes or useful during fresh VMware VM setup.

---

## 1. Contents

- `bootstrap-network.sh`: Automated guest network configuration script for Ubuntu 24.04/22.04 VMs. Auto-detects network interfaces, verifies subnet isolation, backs up previous Netplan files, and applies static IP configuration (`192.168.88.132` for VM1, `192.168.88.133` for VM2).
- `templates/01-netplan-vm1.yaml.example`: Netplan network configuration for VM1 with dual interfaces (`ens33` private lab network + `ens37` NAT/management).
- `templates/01-netplan-vm2.yaml.example`: Netplan network configuration for VM2.
- `templates/hosts.example`: `/etc/hosts` host resolution mappings.
