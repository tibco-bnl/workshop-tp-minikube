#!/bin/bash

################################################################################
# TIBCO Platform on Minikube - Environment Variables
#
# This script sets up all required environment variables for deploying
# TIBCO Platform Control Plane and Data Plane on Minikube.
#
# Usage:
#   source scripts/minikube-env-variables.sh
#
# Last Updated: February 16, 2026
################################################################################

# Colors for output
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export NC='\033[0m' # No Color

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   TIBCO Platform - Minikube Environment Variables Setup       ${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

################################################################################
# Minikube Configuration
################################################################################

echo -e "${GREEN}[1/8] Setting Minikube Configuration...${NC}"

# Minikube profile name
export MINIKUBE_PROFILE="tp"

# Minikube driver (docker, hyperkit, virtualbox)
# For macOS: docker or hyperkit
# For Linux: docker or kvm2
export MINIKUBE_DRIVER="docker"

# Resource allocation
export MINIKUBE_CPUS="8"
export MINIKUBE_MEMORY="20480"  # 20GB in MB
export MINIKUBE_DISK_SIZE="60g"

# Kubernetes version (leave empty for latest stable)
export MINIKUBE_K8S_VERSION=""

echo "  ✓ Minikube Profile: ${MINIKUBE_PROFILE}"
echo "  ✓ Driver: ${MINIKUBE_DRIVER}"
echo "  ✓ CPUs: ${MINIKUBE_CPUS}"
echo "  ✓ Memory: ${MINIKUBE_MEMORY}MB (${MINIKUBE_MEMORY}/1024GB)"
echo "  ✓ Disk: ${MINIKUBE_DISK_SIZE}"

################################################################################
# Network Configuration
################################################################################

echo ""
echo -e "${GREEN}[2/8] Setting Network Configuration...${NC}"

# Tunnel IP (minikube tunnel exposes LoadBalancer services on 127.0.0.1)
export TUNNEL_IP="127.0.0.1"

# DNS suffix (using lvh.me for automatic DNS resolution)
# lvh.me automatically resolves any subdomain to 127.0.0.1
# Example: admin.cp1-my.lvh.me -> 127.0.0.1
# Note: lvh.me is preferred over nip.io because TIBCO router validates FQDN format
# and rejects domains with IP patterns like "127.0.0.1" in the domain name
export DNS_SUFFIX="lvh.me"

# Ingress IP (will be set after minikube tunnel is running)
export INGRESS_IP="${TUNNEL_IP}"

echo "  ✓ Tunnel IP: ${TUNNEL_IP}"
echo "  ✓ DNS Suffix: ${DNS_SUFFIX}"
echo "  ✓ Ingress IP: ${INGRESS_IP}"

################################################################################
# Control Plane Configuration
################################################################################

echo ""
echo -e "${GREEN}[3/8] Setting Control Plane Configuration...${NC}"

# Control Plane instance identifier (alphanumeric, max 5 chars)
export TP_CP_INSTANCE_ID="cp1"

# Control Plane namespace
export TP_CP_NAMESPACE="${TP_CP_INSTANCE_ID}-ns"

# Control Plane domains
export TP_CP_MY_DOMAIN="${TP_CP_INSTANCE_ID}-my.${DNS_SUFFIX}"
export TP_CP_TUNNEL_DOMAIN="${TP_CP_INSTANCE_ID}-tunnel.${DNS_SUFFIX}"

# Subscription name (will be created in the platform admin console)
export TP_SUBSCRIPTION_NAME="benelux"

# Control Plane service account
export TP_CP_SERVICE_ACCOUNT="${TP_CP_INSTANCE_ID}-sa"

# Control Plane version (leave empty for latest)
export TP_CP_VERSION=""

echo "  ✓ Instance ID: ${TP_CP_INSTANCE_ID}"
echo "  ✓ Namespace: ${TP_CP_NAMESPACE}"
echo "  ✓ MY Domain: ${TP_CP_MY_DOMAIN}"
echo "  ✓ TUNNEL Domain: ${TP_CP_TUNNEL_DOMAIN}"

################################################################################
# Data Plane Configuration
################################################################################

echo ""
echo -e "${GREEN}[4/8] Setting Data Plane Configuration...${NC}"

# Data Plane instance identifier (alphanumeric, max 5 chars)
export TP_DP_INSTANCE_ID="dp1"

# Data Plane namespace
export TP_DP_NAMESPACE="${TP_DP_INSTANCE_ID}-ns"

# Data Plane domain (for BWCE/Flogo applications)
export TP_DP_DOMAIN="${TP_DP_INSTANCE_ID}-apps.${DNS_SUFFIX}"

# Data Plane service account
export TP_DP_SERVICE_ACCOUNT="${TP_DP_INSTANCE_ID}-sa"

# Data Plane version (leave empty for latest)
export TP_DP_VERSION=""

echo "  ✓ Instance ID: ${TP_DP_INSTANCE_ID}"
echo "  ✓ Namespace: ${TP_DP_NAMESPACE}"
echo "  ✓ Apps Domain: ${TP_DP_DOMAIN}"

################################################################################
# Storage Configuration
################################################################################

echo ""
echo -e "${GREEN}[5/8] Setting Storage Configuration...${NC}"

# Storage classes (Minikube uses 'standard' for both)
export TP_DISK_STORAGE_CLASS="standard"
export TP_FILE_STORAGE_CLASS="standard"

# Storage sizes
export TP_POSTGRES_STORAGE_SIZE="10Gi"
export TP_CP_STORAGE_SIZE="20Gi"
export TP_DP_STORAGE_SIZE="20Gi"

echo "  ✓ Disk Storage Class: ${TP_DISK_STORAGE_CLASS}"
echo "  ✓ File Storage Class: ${TP_FILE_STORAGE_CLASS}"
echo "  ✓ PostgreSQL Storage: ${TP_POSTGRES_STORAGE_SIZE}"

################################################################################
# Database Configuration (PostgreSQL)
################################################################################

echo ""
echo -e "${GREEN}[6/8] Setting Database Configuration...${NC}"

# PostgreSQL configuration (in-cluster deployment)
export POSTGRES_INSTANCE_NAME="postgres-${TP_CP_INSTANCE_ID}"
export POSTGRES_HOST="${POSTGRES_INSTANCE_NAME}-postgresql.${TP_CP_NAMESPACE}.svc.cluster.local"
export POSTGRES_PORT="5432"
export POSTGRES_DB="postgres"
export POSTGRES_USER="postgres"
export POSTGRES_PASSWORD="postgres123!"

# PostgreSQL resource limits
export POSTGRES_CPU_REQUEST="500m"
export POSTGRES_CPU_LIMIT="2"
export POSTGRES_MEMORY_REQUEST="1Gi"
export POSTGRES_MEMORY_LIMIT="2Gi"

echo "  ✓ Host: ${POSTGRES_HOST}"
echo "  ✓ Port: ${POSTGRES_PORT}"
echo "  ✓ Database: ${POSTGRES_DB}"
echo "  ✓ Username: ${POSTGRES_USER}"
echo "  ✓ Password: ********"

################################################################################
# Container Registry Configuration
################################################################################

echo ""
echo -e "${GREEN}[7/8] Setting Container Registry Configuration...${NC}"

# TIBCO JFrog Container Registry
export CONTAINER_REGISTRY_SERVER="csgprdeuwrepoedge.jfrog.io"
export CONTAINER_REGISTRY_REPOSITORY="tibco-platform-docker-prod"

# Registry credentials - UPDATE THESE WITH YOUR CREDENTIALS
export CONTAINER_REGISTRY_USERNAME="${TP_CONTAINER_REGISTRY_USER:-your-username}"
export CONTAINER_REGISTRY_PASSWORD="${TP_CONTAINER_REGISTRY_PASSWORD:-your-password}"

# Check if credentials are set
if [ "$CONTAINER_REGISTRY_USERNAME" = "your-username" ] || [ "$CONTAINER_REGISTRY_PASSWORD" = "your-password" ]; then
    echo -e "  ${YELLOW}⚠ WARNING: Container registry credentials not set!${NC}"
    echo -e "  ${YELLOW}  Please update CONTAINER_REGISTRY_USERNAME and CONTAINER_REGISTRY_PASSWORD${NC}"
    echo -e "  ${YELLOW}  Or set environment variables:${NC}"
    echo -e "  ${YELLOW}    export TP_CONTAINER_REGISTRY_USER='your-username'${NC}"
    echo -e "  ${YELLOW}    export TP_CONTAINER_REGISTRY_PASSWORD='your-password'${NC}"
else
    echo "  ✓ Registry Server: ${CONTAINER_REGISTRY_SERVER}"
    echo "  ✓ Repository: ${CONTAINER_REGISTRY_REPOSITORY}"
    echo "  ✓ Username: ${CONTAINER_REGISTRY_USERNAME}"
    echo "  ✓ Password: ********"
fi

################################################################################
# Helm Chart Repository
################################################################################

echo ""
echo -e "${GREEN}[8/8] Setting Helm Chart Repository...${NC}"

# TIBCO Platform Helm chart repository
export TP_TIBCO_HELM_CHART_REPO="https://tibcosoftware.github.io/tp-helm-charts"

# Chart versions (leave empty for latest)
export TP_CP_CHART_VERSION=""
export TP_DP_CHART_VERSION=""
export TP_DP_CONFIG_CHART_VERSION="^1.0.0"

echo "  ✓ Helm Repo: ${TP_TIBCO_HELM_CHART_REPO}"

################################################################################
# Ingress Configuration
################################################################################

# Ingress controller type (traefik or nginx)
export TP_INGRESS_CONTROLLER="traefik"

# Ingress class name
export TP_INGRESS_CLASS_NAME="traefik"

################################################################################
# Mail Server Configuration (MailDev)
################################################################################

# MailDev for development email testing
export MAILDEV_ENABLED="true"
export MAILDEV_NAMESPACE="tibco-ext"
export MAILDEV_HOST="development-mailserver.${MAILDEV_NAMESPACE}.svc.cluster.local"
export MAILDEV_SMTP_PORT="1025"
export MAILDEV_HTTP_PORT="1080"
export MAILDEV_DOMAIN="mail.${DNS_SUFFIX}"

################################################################################
# TLS/Certificate Configuration
################################################################################

# Certificate paths (will be set after running generate-certificates-minikube.sh)
export TP_TLS_CERT_MY="certs/cp-my-cert.pem"
export TP_TLS_KEY_MY="certs/cp-my-key.pem"
export TP_TLS_CERT_TUNNEL="certs/cp-tunnel-cert.pem"
export TP_TLS_KEY_TUNNEL="certs/cp-tunnel-key.pem"
export TP_TLS_CERT_COMBINED="certs/combined-cert.pem"
export TP_TLS_KEY_COMBINED="certs/combined-key.pem"

################################################################################
# Observability (Optional)
################################################################################

# Enable observability stack (Prometheus, Grafana, ECK)
export TP_OBSERVABILITY_ENABLED="false"

# Observability namespace
export TP_OBSERVABILITY_NAMESPACE="observability"

################################################################################
# Advanced Configuration
################################################################################

# Log level (debug, info, warn, error)
export TP_LOG_LEVEL="info"

# Enable debug mode
export TP_DEBUG="false"

################################################################################
# Export All Variables Summary
################################################################################

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ Environment Variables Set Successfully!${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Save environment variables to a file for reference
cat > .env-minikube <<EOF_ENV
# TIBCO Platform Minikube Environment Variables
# Generated: $(date)

# Minikube Configuration
MINIKUBE_PROFILE=${MINIKUBE_PROFILE}
MINIKUBE_DRIVER=${MINIKUBE_DRIVER}
MINIKUBE_CPUS=${MINIKUBE_CPUS}
MINIKUBE_MEMORY=${MINIKUBE_MEMORY}
MINIKUBE_DISK_SIZE=${MINIKUBE_DISK_SIZE}

# Network Configuration
TUNNEL_IP=${TUNNEL_IP}
DNS_SUFFIX=${DNS_SUFFIX}
INGRESS_IP=${INGRESS_IP}

# Control Plane Configuration
TP_CP_INSTANCE_ID=${TP_CP_INSTANCE_ID}
TP_CP_NAMESPACE=${TP_CP_NAMESPACE}
TP_CP_MY_DOMAIN=${TP_CP_MY_DOMAIN}
TP_CP_TUNNEL_DOMAIN=${TP_CP_TUNNEL_DOMAIN}

# Data Plane Configuration
TP_DP_INSTANCE_ID=${TP_DP_INSTANCE_ID}
TP_DP_NAMESPACE=${TP_DP_NAMESPACE}
TP_DP_DOMAIN=${TP_DP_DOMAIN}

# Storage Configuration
TP_DISK_STORAGE_CLASS=${TP_DISK_STORAGE_CLASS}
TP_FILE_STORAGE_CLASS=${TP_FILE_STORAGE_CLASS}

# Database Configuration
POSTGRES_HOST=${POSTGRES_HOST}
POSTGRES_PORT=${POSTGRES_PORT}
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}

# Container Registry
CONTAINER_REGISTRY_SERVER=${CONTAINER_REGISTRY_SERVER}
CONTAINER_REGISTRY_USERNAME=${CONTAINER_REGISTRY_USERNAME}
CONTAINER_REGISTRY_PASSWORD=${CONTAINER_REGISTRY_PASSWORD}

# Helm Repository
TP_TIBCO_HELM_CHART_REPO=${TP_TIBCO_HELM_CHART_REPO}

# Ingress Configuration
TP_INGRESS_CONTROLLER=${TP_INGRESS_CONTROLLER}
TP_INGRESS_CLASS_NAME=${TP_INGRESS_CLASS_NAME}
EOF_ENV

echo -e "${GREEN}Environment variables saved to: .env-minikube${NC}"
echo ""

echo -e "${YELLOW}Quick Reference:${NC}"
echo -e "  Admin Console:    https://admin.${TP_CP_MY_DOMAIN}"
echo -e "  Subscription URL: https://${TP_SUBSCRIPTION_NAME}.${TP_CP_MY_DOMAIN}"
echo -e "  Mail UI:          https://mail.${DNS_SUFFIX}"
echo -e "  Provisioner:      https://provisioner.${DNS_SUFFIX}"
echo -e "  Tekton:           https://tekton.${DNS_SUFFIX}"
echo -e "  BWCE Capability:  https://bwce.${TP_CP_MY_DOMAIN}"
echo -e "  Flogo Capability: https://flogo.${TP_CP_MY_DOMAIN}"
echo ""

echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Update container registry credentials if needed"
echo -e "  2. Start Minikube: minikube start -p ${MINIKUBE_PROFILE}"
echo -e "  3. Start tunnel: minikube tunnel -p ${MINIKUBE_PROFILE} (in separate terminal)"
echo -e "  4. Follow the setup guide: howto/how-to-cp-and-dp-minikube-setup-guide.md"
echo ""
