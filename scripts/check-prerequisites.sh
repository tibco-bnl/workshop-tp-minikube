#!/bin/bash

################################################################################
# TIBCO Platform Minikube - Prerequisites Verification Script
#
# This script checks all prerequisites for deploying TIBCO Platform on Minikube
#
# Usage:
#   ./check-prerequisites.sh
#
# Last Updated: February 16, 2026
################################################################################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

check_pass() {
    echo -e "  ${GREEN}✅ PASS${NC}: $1"
    ((PASS_COUNT++))
}

check_fail() {
    echo -e "  ${RED}❌ FAIL${NC}: $1"
    ((FAIL_COUNT++))
}

check_warn() {
    echo -e "  ${YELLOW}⚠️  WARN${NC}: $1"
    ((WARN_COUNT++))
}

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  TIBCO Platform Minikube - Prerequisites Verification         ${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Check CPU cores
echo -e "${BLUE}[1/10] Checking CPU cores...${NC}"
if [[ "$OSTYPE" == "darwin"* ]]; then
    CORES=$(sysctl -n hw.ncpu)
else
    CORES=$(nproc)
fi
echo "  Available cores: $CORES"
if [ $CORES -ge 8 ]; then
    check_pass "$CORES cores available (Recommended: 8+)"
elif [ $CORES -ge 6 ]; then
    check_pass "$CORES cores available (Minimum: 6)"
else
    check_fail "Only $CORES cores available. Need at least 6 cores."
fi
echo ""

# Check RAM
echo -e "${BLUE}[2/10] Checking RAM...${NC}"
if [[ "$OSTYPE" == "darwin"* ]]; then
    RAM_GB=$(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))
else
    RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
fi
echo "  Available RAM: ${RAM_GB}GB"
if [ $RAM_GB -ge 20 ]; then
    check_pass "${RAM_GB}GB RAM available (Recommended: 20GB+)"
elif [ $RAM_GB -ge 16 ]; then
    check_pass "${RAM_GB}GB RAM available (Minimum: 16GB)"
else
    check_fail "Only ${RAM_GB}GB RAM available. Need at least 16GB."
fi
echo ""

# Check disk space
echo -e "${BLUE}[3/10] Checking disk space...${NC}"
if [[ "$OSTYPE" == "darwin"* ]]; then
    DISK_GB=$(df -g ~ | awk 'NR==2 {print $4}')
else
    DISK_GB=$(df -BG ~ | awk 'NR==2 {print $4}' | sed 's/G//')
fi
echo "  Available disk space: ${DISK_GB}GB"
if [ $DISK_GB -ge 60 ]; then
    check_pass "${DISK_GB}GB disk space available (Recommended: 60GB+)"
elif [ $DISK_GB -ge 50 ]; then
    check_pass "${DISK_GB}GB disk space available (Minimum: 50GB)"
else
    check_fail "Only ${DISK_GB}GB disk space available. Need at least 50GB."
fi
echo ""

# Check kubectl
echo -e "${BLUE}[4/10] Checking kubectl...${NC}"
if command -v kubectl &> /dev/null; then
    KUBECTL_VERSION=$(kubectl version --client --short 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || kubectl version --client 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    echo "  Version: $KUBECTL_VERSION"
    check_pass "kubectl is installed"
else
    check_fail "kubectl not installed"
    echo "  Install: brew install kubectl (macOS) or see https://kubernetes.io/docs/tasks/tools/"
fi
echo ""

# Check Helm
echo -e "${BLUE}[5/10] Checking Helm...${NC}"
if command -v helm &> /dev/null; then
    HELM_VERSION=$(helm version --short 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+')
    echo "  Version: $HELM_VERSION"
    HELM_MAJOR=$(echo $HELM_VERSION | cut -d. -f1 | sed 's/v//')
    HELM_MINOR=$(echo $HELM_VERSION | cut -d. -f2)
    if [ "$HELM_MAJOR" -ge 3 ] && [ "$HELM_MINOR" -ge 17 ]; then
        check_pass "Helm 3.17.0+ is installed"
    else
        check_warn "Helm version may be too old. Recommended: 3.17.0+"
    fi
else
    check_fail "Helm not installed"
    echo "  Install: brew install helm (macOS) or curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash"
fi
echo ""

# Check Minikube
echo -e "${BLUE}[6/10] Checking Minikube...${NC}"
if command -v minikube &> /dev/null; then
    MINIKUBE_VERSION=$(minikube version --short 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+')
    echo "  Version: $MINIKUBE_VERSION"
    check_pass "Minikube is installed"
else
    check_fail "Minikube not installed"
    echo "  Install: brew install minikube (macOS) or see https://minikube.sigs.k8s.io/docs/start/"
fi
echo ""

# Check Docker
echo -e "${BLUE}[7/10] Checking Docker...${NC}"
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    echo "  Version: $DOCKER_VERSION"
    if docker ps &> /dev/null; then
        echo "  Docker daemon: Running"
        check_pass "Docker is installed and running"
    else
        check_fail "Docker is installed but daemon is not running"
        echo "  Start Docker Desktop (macOS) or run: sudo systemctl start docker (Linux)"
    fi
else
    check_fail "Docker not installed"
    echo "  Install: Download Docker Desktop from https://www.docker.com/products/docker-desktop"
fi
echo ""

# Check OpenSSL
echo -e "${BLUE}[8/10] Checking OpenSSL...${NC}"
if command -v openssl &> /dev/null; then
    OPENSSL_VERSION=$(openssl version | awk '{print $2}')
    echo "  Version: $OPENSSL_VERSION"
    check_pass "OpenSSL is installed"
else
    check_fail "OpenSSL not installed"
    echo "  Install: brew install openssl (macOS) or sudo apt-get install openssl (Linux)"
fi
echo ""

# Check DNS resolution
echo -e "${BLUE}[9/10] Checking DNS resolution (nip.io)...${NC}"
TEST_RESULT=$(nslookup test.127.0.0.1.nip.io 2>&1)
if echo "$TEST_RESULT" | grep -q "127.0.0.1"; then
    echo "  nip.io resolution: Working"
    check_pass "DNS resolution via nip.io is working"
else
    check_warn "nip.io resolution failed (may use sslip.io or /etc/hosts as fallback)"
    echo "  Alternative: Use sslip.io or manual /etc/hosts entries"
fi
echo ""

# Check port availability
echo -e "${BLUE}[10/10] Checking port availability...${NC}"
PORT_80_CHECK=$(sudo lsof -i :80 2>&1)
PORT_443_CHECK=$(sudo lsof -i :443 2>&1)

if echo "$PORT_80_CHECK" | grep -q "COMMAND"; then
    check_warn "Port 80 is in use. You may need to stop the service using it."
    echo "$PORT_80_CHECK" | head -3
else
    echo "  Port 80: Available"
fi

if echo "$PORT_443_CHECK" | grep -q "COMMAND"; then
    check_warn "Port 443 is in use. You may need to stop the service using it."
    echo "$PORT_443_CHECK" | head -3
else
    echo "  Port 443: Available"
fi

if ! echo "$PORT_80_CHECK" | grep -q "COMMAND" && ! echo "$PORT_443_CHECK" | grep -q "COMMAND"; then
    check_pass "Ports 80 and 443 are available"
fi
echo ""

# Summary
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Summary                                                       ${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${GREEN}✅ Passed:${NC} $PASS_COUNT"
echo -e "  ${YELLOW}⚠️  Warnings:${NC} $WARN_COUNT"
echo -e "  ${RED}❌ Failed:${NC} $FAIL_COUNT"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "${GREEN}🎉 All prerequisites are satisfied!${NC}"
    echo -e "${GREEN}You are ready to proceed with TIBCO Platform installation.${NC}"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo "  1. Review: cat howto/prerequisites-checklist.md"
    echo "  2. Set environment variables: source scripts/minikube-env-variables.sh"
    echo "  3. Follow setup guide: howto/how-to-cp-and-dp-minikube-setup-guide.md"
    echo ""
    exit 0
else
    echo -e "${RED}❌ Some prerequisites are not met.${NC}"
    echo -e "${RED}Please install the missing components and run this script again.${NC}"
    echo ""
    echo -e "${BLUE}For detailed installation instructions, see:${NC}"
    echo "  howto/prerequisites-checklist.md"
    echo ""
    exit 1
fi
