# Prerequisites Checklist for TIBCO Platform on Minikube

**Document Purpose**: Comprehensive checklist of prerequisites and requirements for deploying TIBCO Platform Control Plane and Data Plane on Minikube.

**Target Audience**: DevOps engineers, Platform administrators, Developers

**Completion Time**: 30-60 minutes (first-time setup)

**Last Updated**: February 16, 2026

---

## Table of Contents

- [Overview](#overview)
- [1. Hardware Requirements](#1-hardware-requirements)
- [2. Operating System Requirements](#2-operating-system-requirements)
- [3. Required Software Tools](#3-required-software-tools)
- [4. TIBCO Container Registry Access](#4-tibco-container-registry-access)
- [5. Minikube Configuration](#5-minikube-configuration)
- [6. Network Requirements](#6-network-requirements)
- [7. Storage Requirements](#7-storage-requirements)
- [8. Knowledge Prerequisites](#8-knowledge-prerequisites)
- [9. Preparation Checklist](#9-preparation-checklist)

---

## Overview

This document provides a complete checklist of all prerequisites needed before starting TIBCO Platform deployment on Minikube. Complete all items in this checklist before beginning the installation to ensure a smooth deployment experience.

---

## 1. Hardware Requirements

### ✅ Minimum Requirements

| Component | Requirement | Verification Command |
|-----------|-------------|---------------------|
| **CPU Cores** | 6 cores | macOS: `sysctl -n hw.ncpu`<br>Linux: `nproc` |
| **RAM** | 16GB | macOS: `sysctl hw.memsize \| awk '{print $2/1024/1024/1024" GB"}'`<br>Linux: `free -h` |
| **Disk Space** | 50GB free | `df -h ~` |
| **Architecture** | x86_64 (Intel/AMD) or ARM64 (Apple Silicon) | `uname -m` |

### ⭐ Recommended Requirements

| Component | Recommendation | Benefit |
|-----------|----------------|---------|
| **CPU Cores** | 8+ cores | Better performance, faster deployments |
| **RAM** | 20GB | Smoother operation, more headroom |
| **Disk Space** | 60GB free | More storage for images and data |
| **SSD** | NVMe SSD | Faster I/O operations |

### 📊 Expected Resource Usage After Deployment

| Component | Minikube VM | Control Plane | Data Plane | Total |
|-----------|-------------|---------------|------------|-------|
| **CPU** | 2 cores | 2-3 cores | 1-2 cores | ~6 cores |
| **Memory** | 4GB | 8GB | 4GB | ~16GB |
| **Disk** | 10GB | 20GB | 10GB | ~40GB |

**Note**: These are estimates. Actual usage may vary based on workload and capabilities enabled.

---

## 2. Operating System Requirements

### ✅ Supported Operating Systems

#### macOS
- ✅ macOS 11.x (Big Sur) or higher
- ✅ macOS 12.x (Monterey) - Recommended
- ✅ macOS 13.x (Ventura) - Recommended
- ✅ macOS 14.x (Sonoma) - Fully tested
- ✅ Both Intel and Apple Silicon (M1/M2) supported

**Verify macOS Version:**
```bash
sw_vers
# ProductName:        macOS
# ProductVersion:     14.x
# BuildVersion:       23x
```

#### Linux
- ✅ Ubuntu 20.04 LTS or higher
- ✅ Ubuntu 22.04 LTS - Recommended
- ✅ Ubuntu 24.04 LTS - Fully tested
- ✅ Debian 11 or higher
- ✅ Fedora 36 or higher
- ✅ RHEL 8 or higher / Rocky Linux 8+

**Verify Linux Version:**
```bash
cat /etc/os-release
# NAME="Ubuntu"
# VERSION="22.04.x LTS (Jammy Jellyfish)"
```

#### ❌ Not Supported
- ❌ Windows 10/11 (WSL2 may work but not officially supported in this guide)
- ❌ Older macOS versions (< 11.x)
- ❌ Older Linux distributions (Ubuntu < 20.04)

---

## 3. Required Software Tools

### 3.1 Kubernetes CLI (kubectl)

**Required Version**: Latest stable (1.28.0+)

**Installation:**

```bash
# macOS (Homebrew)
brew install kubectl

# macOS (Direct download)
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/darwin/amd64/kubectl"
# OR for Apple Silicon:
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/darwin/arm64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Linux
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
```

**Verification:**
```bash
kubectl version --client
# Client Version: v1.31.0
```

### 3.2 Helm

**Required Version**: 3.17.0 or higher

**Installation:**

```bash
# macOS (Homebrew)
brew install helm

# Linux
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Or download directly
curl -LO https://get.helm.sh/helm-v3.17.0-linux-amd64.tar.gz
tar -zxvf helm-v3.17.0-linux-amd64.tar.gz
sudo mv linux-amd64/helm /usr/local/bin/
```

**Verification:**
```bash
helm version
# version.BuildInfo{Version:"v3.17.0", ...}
```

### 3.3 Minikube

**Required Version**: 1.34.0 or higher

**Installation:**

```bash
# macOS (Homebrew)
brew install minikube

# macOS (Direct download - Intel)
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-darwin-amd64
sudo install minikube-darwin-amd64 /usr/local/bin/minikube

# macOS (Direct download - Apple Silicon)
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-darwin-arm64
sudo install minikube-darwin-arm64 /usr/local/bin/minikube

# Linux
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
```

**Verification:**
```bash
minikube version
# minikube version: v1.34.0
```

### 3.4 Container Runtime (Docker)

**Required**: Docker or compatible container runtime

**Installation:**

```bash
# macOS
# Download Docker Desktop from https://www.docker.com/products/docker-desktop
# OR using Homebrew:
brew install --cask docker

# Linux (Docker)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
# Log out and back in for group changes to take effect
```

**Verification:**
```bash
docker --version
# Docker version 24.0.7, build ...

docker ps
# CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
```

**Alternative Container Runtimes** (Advanced users):
- Podman (may require additional configuration)
- containerd (built into Minikube)

### 3.5 OpenSSL

**Required Version**: 1.1.1 or higher

**Installation:**

```bash
# macOS (usually pre-installed, but can upgrade via Homebrew)
brew install openssl

# Linux (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install openssl

# Linux (RHEL/Rocky/Fedora)
sudo dnf install openssl
```

**Verification:**
```bash
openssl version
# OpenSSL 3.0.x or 1.1.1x
```

### 3.6 Git (Optional but Recommended)

**For cloning this repository**

```bash
# macOS
brew install git

# Linux (Ubuntu/Debian)
sudo apt-get install git

# Linux (RHEL/Rocky/Fedora)
sudo dnf install git
```

**Verification:**
```bash
git --version
# git version 2.39.0 or higher
```

### 3.7 Additional Utilities (Recommended)

```bash
# jq - JSON processor (useful for parsing kubectl output)
brew install jq           # macOS
sudo apt-get install jq   # Linux

# yq - YAML processor
brew install yq           # macOS
sudo snap install yq      # Linux

# curl and wget (usually pre-installed)
# Verify:
curl --version
wget --version
```

---

## 4. TIBCO Container Registry Access

### ✅ Required Credentials

You need valid credentials for TIBCO's JFrog container registry:

| Item | Required Value | Where to Get |
|------|----------------|--------------|
| **Registry URL** | `csgprdeuwrepoedge.jfrog.io` | Fixed |
| **Username** | Your TIBCO JFrog username | From TIBCO |
| **Password** | Your TIBCO JFrog password/token | From TIBCO |
| **Repository** | `tibco-platform-docker-prod` | Fixed |

### 📋 How to Obtain Credentials

1. **Contact TIBCO Sales or Support**
   - Request access to TIBCO Container Registry
   - Provide your organization details
   - Specify TIBCO Platform version needed

2. **TIBCO Community Account** (if available)
   - Login to TIBCO Community
   - Navigate to Downloads section
   - Look for container registry credentials

3. **Existing TIBCO Customer**
   - Contact your TIBCO account representative
   - Submit a support ticket
   - Reference your existing license/subscription

### ✅ Verify Registry Access

```bash
# Test login (replace with your credentials)
docker login csgprdeuwrepoedge.jfrog.io
Username: your-username
Password: your-password

# Expected output:
# Login Succeeded

# Test pulling an image (example)
docker pull csgprdeuwrepoedge.jfrog.io/tibco-platform-docker-prod/common-postgresql:16.4.0-debian-12-r14

# Expected output:
# Status: Downloaded newer image for csgprdeuwrepoedge.jfrog.io/tibco-platform-docker-prod/common-postgresql:16.4.0-debian-12-r14
```

### ⚠️ Important Notes

- Credentials are **REQUIRED** - deployment will fail without them
- Keep credentials secure
- Do not commit credentials to version control
- Use environment variables for credentials (our scripts support this)

---

## 5. Minikube Configuration

### ✅ Driver Selection

Minikube supports multiple drivers. Choose based on your OS:

#### macOS Drivers

| Driver | Recommendation | Notes |
|--------|----------------|-------|
| **docker** | ✅ Recommended | Easiest, uses Docker Desktop |
| **hyperkit** | ✅ Alternative | Native hypervisor, good performance |
| qemu | ⚠️ Experimental | For Apple Silicon if others don't work |
| virtualbox | ❌ Not recommended | Slower, more complex |

#### Linux Drivers

| Driver | Recommendation | Notes |
|--------|----------------|-------|
| **docker** | ✅ Recommended | Easiest, uses Docker |
| **kvm2** | ✅ Alternative | Native hypervisor, best performance |
| virtualbox | ⚠️ OK | Widely compatible but slower |

### ✅ Driver Installation

**Docker driver (macOS and Linux)**:
```bash
# Requires Docker Desktop (macOS) or Docker Engine (Linux)
# See section 3.4 above
```

**Hyperkit driver (macOS only)**:
```bash
brew install hyperkit
brew install docker-machine-driver-hyperkit
sudo chown root:wheel /usr/local/bin/docker-machine-driver-hyperkit
sudo chmod u+s /usr/local/bin/docker-machine-driver-hyperkit
```

**KVM2 driver (Linux only)**:
```bash
# Ubuntu/Debian
sudo apt-get install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils

# Install KVM2 driver
curl -LO https://storage.googleapis.com/minikube/releases/latest/docker-machine-driver-kvm2
sudo install docker-machine-driver-kvm2 /usr/local/bin/

# Add user to libvirt group
sudo usermod -a -G libvirt $(whoami)
```

### ✅ Verify Driver

```bash
# List available drivers
minikube start --help | grep -A 20 "driver string"

# Test selected driver
minikube start -p test --driver=docker --dry-run
# Should not show errors
```

---

## 6. Network Requirements

### ✅ Internet Connectivity

**Required for**:
- Downloading container images from TIBCO registry
- Downloading Helm charts
- DNS resolution via lvh.me (automatic for 127.0.0.1)
- Package installations

**Bandwidth Requirements**:
- Initial setup: ~10-20 GB download
- Control Plane images: ~5-8 GB
- Data Plane images: ~3-5 GB
- PostgreSQL and other dependencies: ~2-3 GB

### ✅ DNS Resolution

**Using lvh.me (Recommended)**:
- No configuration needed
- Automatic DNS resolution (all subdomains resolve to 127.0.0.1)
- Works in most networks
- Compatible with TIBCO router FQDN validation

**Test lvh.me access**:
```bash
nslookup test.lvh.me
# Should return 127.0.0.1

# Test subdomain resolution
nslookup account.cp1-my.lvh.me
# Should also return 127.0.0.1
```

**Note**: We use lvh.me instead of nip.io because TIBCO's router component validates FQDNs and rejects domains containing IP patterns (like `127.0.0.1.nip.io`).

**If lvh.me is blocked by your network**:
- Fallback to `/etc/hosts` entries
- Manual DNS configuration required (documented in setup guide)

### ✅ Firewall and Proxy

**Outbound Access Required**:
| Destination | Port | Purpose |
|-------------|------|---------|
| csgprdeuwrepoedge.jfrog.io | 443 | Container images |
| tibcosoftware.github.io | 443 | Helm charts |

```bash
# Set proxy environment variables
export HTTP_PROXY="http://proxy.company.com:8080"
export HTTPS_PROXY="http://proxy.company.com:8080"
export NO_PROXY="localhost,127.0.0.1,.local"

# Configure Docker proxy (if needed)
# Edit ~/.docker/config.json or Docker Desktop settings

# Configure Minikube to use proxy
minikube start --docker-env HTTP_PROXY=$HTTP_PROXY \
              --docker-env HTTPS_PROXY=$HTTPS_PROXY \
              --docker-env NO_PROXY=$NO_PROXY
```

### ✅ Port Availability

**Ports used locally**:
| Port | Service | Can Remap? |
|------|---------|------------|
| 80 | HTTP (Minikube tunnel) | No |
| 443 | HTTPS (Minikube tunnel) | No |
| 8443 | Kubernetes API (default) | Yes (Minikube) |

**Check port availability**:
```bash
# Check if ports 80 and 443 are available
sudo lsof -i :80
sudo lsof -i :443

# If occupied, stop the service using them or use different ports
```

---

## 7. Storage Requirements

### ✅ Disk Space Breakdown

| Component | Size | Purpose |
|-----------|------|---------|
| Minikube VM | 10-15 GB | Base VM and Kubernetes |
| Container Images | 15-20 GB | TIBCO Platform images |
| PostgreSQL Data | 10 GB | Database storage |
| Control Plane PVCs | 10-15 GB | CP persistent data |
| Data Plane PVCs | 5-10 GB | DP persistent data |
| **Total** | **50-70 GB** | Complete deployment |

### ✅ Verify Available Space

```bash
# Check available disk space
df -h ~

# Expected output showing >50GB free:
# Filesystem      Size   Used  Avail Capacity
# /dev/disk1s1   500Gi  400Gi  100Gi    80%
```

### ✅ Storage Performance

**Recommended**:
- SSD (NVMe preferred)
- >500 MB/s read/write speed

**Test disk speed** (optional):
```bash
# macOS
diskutil info disk0 | grep "Solid State"

# Linux
sudo hdparm -Tt /dev/sda

# Using dd (cross-platform)
dd if=/dev/zero of=/tmp/test bs=1M count=1000 oflag=direct
# Should show >200 MB/s
```

---

## 8. Knowledge Prerequisites

### ✅ Required Knowledge

- ☑️ Basic Linux command line (bash/zsh)
- ☑️ Basic understanding of Kubernetes concepts (pods, services, namespaces)
- ☑️ Basic understanding of containers and Docker
- ☑️ Ability to edit text files and run commands
- ☑️ Basic networking concepts (DNS, ports, protocols)

### ⭐ Helpful (But Not Required)

- Helm charts and Kubernetes package management
- YAML syntax and structure
- SSL/TLS certificates
- PostgreSQL database administration
- TIBCO Platform concepts

### 📚 Learning Resources

If you're new to these technologies:

**Kubernetes**:
- [Kubernetes Official Documentation](https://kubernetes.io/docs/home/)
- [Kubernetes Basics Tutorial](https://kubernetes.io/docs/tutorials/kubernetes-basics/)

**Docker**:
- [Docker Get Started](https://docs.docker.com/get-started/)
- [Docker for Beginners](https://docker-curriculum.com/)

**Helm**:
- [Helm Documentation](https://helm.sh/docs/)
- [Helm Quickstart](https://helm.sh/docs/intro/quickstart/)

---

## 9. Preparation Checklist

### Before Starting Installation

Use this checklist to ensure you're ready:

#### ✅ Hardware Checklist

- [ ] CPU: 6+ cores available
- [ ] RAM: 16+ GB available
- [ ] Disk: 50+ GB free space
- [ ] System is connected to power (laptops)

#### ✅ Software Checklist

- [ ] kubectl installed and working
- [ ] Helm 3.17.0+ installed
- [ ] Minikube 1.34.0+ installed
- [ ] Docker installed and running
- [ ] OpenSSL 1.1.1+ installed
- [ ] Git installed (optional)

#### ✅ Access Checklist

- [ ] TIBCO JFrog registry credentials obtained
- [ ] Docker login to TIBCO registry successful
- [ ] Internet connectivity verified
- [ ] DNS resolution (lvh.me) working
- [ ] Ports 80 and 443 available

#### ✅ Environment Checklist

- [ ] Repository cloned: `git clone <repo-url>`
- [ ] Changed to directory: `cd workshop-tp-minikube`
- [ ] Environment variables reviewed: `cat scripts/minikube-env-variables.sh`
- [ ] Registry credentials updated in script
- [ ] Terminal window(s) available (need 2: main + tunnel)

#### ✅ Time Allocation

- [ ] 2-3 hours available for initial setup
- [ ] No urgent meetings or deadlines during setup
- [ ] Time to troubleshoot if issues arise

#### ✅ Final Checks

- [ ] Read the [setup guide](./how-to-cp-and-dp-minikube-setup-guide.md) overview
- [ ] Understand the architecture
- [ ] Know where to find troubleshooting help
- [ ] Have TIBCO support contact available (if needed)

---

## 10. Quick Verification Script

Run this script to verify all prerequisites automatically:

```bash
#!/bin/bash

echo "TIBCO Platform Minikube - Prerequisites Verification"
echo "===================================================="
echo ""

# Check CPU
echo "Checking CPU cores..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    CORES=$(sysctl -n hw.ncpu)
else
    CORES=$(nproc)
fi
echo "  Available cores: $CORES"
[ $CORES -ge 6 ] && echo "  ✅ PASS" || echo "  ❌ FAIL: Need at least 6 cores"
echo ""

# Check RAM
echo "Checking RAM..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    RAM_GB=$(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))
else
    RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
fi
echo "  Available RAM: ${RAM_GB}GB"
[ $RAM_GB -ge 16 ] && echo "  ✅ PASS" || echo "  ❌ FAIL: Need at least 16GB"
echo ""

# Check disk space
echo "Checking disk space..."
DISK_GB=$(df -BG ~ | awk 'NR==2 {print $4}' | sed 's/G//')
echo "  Available disk: ${DISK_GB}GB"
[ $DISK_GB -ge 50 ] && echo "  ✅ PASS" || echo "  ❌ FAIL: Need at least 50GB"
echo ""

# Check kubectl
echo "Checking kubectl..."
if command -v kubectl &> /dev/null; then
    echo "  Version: $(kubectl version --client --short 2>/dev/null || kubectl version --client)"
    echo "  ✅ PASS"
else
    echo "  ❌ FAIL: kubectl not installed"
fi
echo ""

# Check Helm
echo "Checking Helm..."
if command -v helm &> /dev/null; then
    echo "  Version: $(helm version --short)"
    echo "  ✅ PASS"
else
    echo "  ❌ FAIL: Helm not installed"
fi
echo ""

# Check Minikube
echo "Checking Minikube..."
if command -v minikube &> /dev/null; then
    echo "  Version: $(minikube version --short)"
    echo "  ✅ PASS"
else
    echo "  ❌ FAIL: Minikube not installed"
fi
echo ""

# Check Docker
echo "Checking Docker..."
if command -v docker &> /dev/null; then
    echo "  Version: $(docker --version)"
    if docker ps &> /dev/null; then
        echo "  Docker daemon: Running"
        echo "  ✅ PASS"
    else
        echo "  ❌ FAIL: Docker daemon not running"
    fi
else
    echo "  ❌ FAIL: Docker not installed"
fi
echo ""

# Check OpenSSL
echo "Checking OpenSSL..."
if command -v openssl &> /dev/null; then
    echo "  Version: $(openssl version)"
    echo "  ✅ PASS"
else
    echo "  ❌ FAIL: OpenSSL not installed"
fi
echo ""

# Check DNS resolution
echo "Checking DNS resolution (lvh.me)..."
if nslookup test.lvh.me &> /dev/null; then
    echo "  lvh.me resolution: Working (✅ Resolves to 127.0.0.1)"
    echo "  ✅ PASS"
else
    echo "  ⚠️  WARNING: lvh.me resolution failed (may need /etc/hosts fallback)"
fi
echo ""

echo "===================================================="
echo "Prerequisites check complete!"
echo ""
```

Save this as `check-prerequisites.sh`, make it executable with `chmod +x check-prerequisites.sh`, and run it with `./check-prerequisites.sh`.

---

## Summary

Once you've completed all items in this checklist:

1. ✅ All hardware requirements met
2. ✅ All software tools installed and verified
3. ✅ TIBCO registry credentials obtained and tested
4. ✅ Network connectivity verified
5. ✅ Storage space available
6. ✅ Knowledge prerequisites reviewed

**You are ready to proceed with the installation!**

**Next Step**: Follow the [Complete Setup Guide](./how-to-cp-and-dp-minikube-setup-guide.md)

---

**Document Version**: 1.1  
**Last Updated**: February 17, 2026  
**Maintained by**: TIBCO Platform Workshop Team
