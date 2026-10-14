# PipeJack Deployment Kit — Shared Assets and Network Templates

This directory contains shared configuration templates, network planning examples, and operating system configuration snippets that are common across both nodes or useful during fresh VMware VM setup.

---

## 1. Contents

- `templates/01-netplan-vm1.yaml.example`: Netplan network configuration for VM1 with dual interfaces (`ens33` private lab network + `ens37` NAT/management).
- `templates/01-netplan-vm2.yaml.example`: Netplan network configuration for VM2.
- `templates/hosts.example`: `/etc/hosts` host resolution mappings.
