#!/bin/bash

################################################################################
# TIBCO Platform - SSL Certificate Generation Script for Minikube
# 
# This script generates self-signed SSL certificates for TIBCO Platform
# Control Plane and Data Plane on Minikube with comprehensive SAN coverage.
#
# ⚠️  WARNING: Self-signed certificates are for DEVELOPMENT/TESTING ONLY!
# For production, use certificates from a trusted Certificate Authority.
#
# Usage:
#   ./generate-certificates-minikube.sh
#
# Prerequisites:
#   - openssl installed
#   - Environment variables set (source scripts/minikube-env-variables.sh first)
#
# Last Updated: February 16, 2026
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

################################################################################
# Functions
################################################################################

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

check_prerequisites() {
    log_step "Checking prerequisites..."
    
    # Check if openssl is installed
    if ! command -v openssl &> /dev/null; then
        log_error "openssl is not installed. Please install openssl first."
        echo "  macOS: brew install openssl"
        echo "  Linux: sudo apt-get install openssl"
        exit 1
    fi
    
    # Check if required environment variables are set
    if [ -z "$TP_CP_MY_DOMAIN" ] || [ -z "$TP_CP_TUNNEL_DOMAIN" ] || [ -z "$TP_DP_DOMAIN" ]; then
        log_error "Required environment variables not set."
        log_error "Please source minikube-env-variables.sh first:"
        log_error "  source scripts/minikube-env-variables.sh"
        exit 1
    fi
    
    log_info "Prerequisites check passed!"
    log_info "  OpenSSL version: $(openssl version)"
}

create_cert_directory() {
    CERT_DIR="$(pwd)/certs"
    
    if [ -d "$CERT_DIR" ]; then
        log_warn "Certificate directory already exists: $CERT_DIR"
        read -p "Do you want to overwrite existing certificates? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Certificate generation cancelled."
            exit 0
        fi
        rm -rf "$CERT_DIR"
    fi
    
    mkdir -p "$CERT_DIR"
    log_info "Certificate directory created: $CERT_DIR"
}

generate_ca_certificate() {
    log_step "Generating Certificate Authority (CA)..."
    
    local ca_key="${CERT_DIR}/ca-key.pem"
    local ca_cert="${CERT_DIR}/ca-cert.pem"
    
    # Generate CA private key
    openssl genrsa -out "$ca_key" 4096 2>/dev/null
    log_info "  ✓ CA private key generated: $ca_key"
    
    # Generate CA certificate
    openssl req -x509 -new -nodes -key "$ca_key" -sha256 -days 3650 \
        -out "$ca_cert" \
        -subj "/C=US/ST=California/L=San Francisco/O=TIBCO Platform/OU=Development/CN=TIBCO Platform Minikube CA" \
        2>/dev/null
    log_info "  ✓ CA certificate generated: $ca_cert"
    log_info "  ✓ Valid for: 3650 days (10 years)"
}

generate_certificate_with_sans() {
    local cert_name=$1
    local common_name=$2
    shift 2
    local sans=("$@")
    
    log_step "Generating certificate: $cert_name"
    log_info "  Common Name: $common_name"
    
    local key_file="${CERT_DIR}/${cert_name}-key.pem"
    local csr_file="${CERT_DIR}/${cert_name}-csr.pem"
    local cert_file="${CERT_DIR}/${cert_name}-cert.pem"
    local ext_file="${CERT_DIR}/${cert_name}-ext.cnf"
    
    # Generate private key
    openssl genrsa -out "$key_file" 2048 2>/dev/null
    log_info "  ✓ Private key generated"
    
    # Create OpenSSL config for SAN
    cat > "$ext_file" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=US
ST=California
L=San Francisco
O=TIBCO Platform
OU=Minikube Development
CN=${common_name}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
EOF

    # Add all SANs
    local dns_index=1
    local ip_index=1
    
    for san in "${sans[@]}"; do
        if [[ $san =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "IP.${ip_index} = ${san}" >> "$ext_file"
            ((ip_index++))
        else
            echo "DNS.${dns_index} = ${san}" >> "$ext_file"
            ((dns_index++))
        fi
    done
    
    # Generate CSR
    openssl req -new -key "$key_file" -out "$csr_file" \
        -config "$ext_file" 2>/dev/null
    log_info "  ✓ Certificate Signing Request generated"
    
    # Generate certificate signed by CA
    openssl x509 -req -in "$csr_file" \
        -CA "${CERT_DIR}/ca-cert.pem" \
        -CAkey "${CERT_DIR}/ca-key.pem" \
        -CAcreateserial \
        -out "$cert_file" \
        -days 825 \
        -sha256 \
        -extensions v3_req \
        -extfile "$ext_file" 2>/dev/null
    log_info "  ✓ Certificate generated and signed by CA"
    log_info "  ✓ Valid for: 825 days (~2 years)"
    
    # Verify certificate
    log_info "  ✓ Certificate SANs:"
    openssl x509 -in "$cert_file" -noout -text | grep -A 50 "Subject Alternative Name" | grep -E "DNS:|IP:" | sed 's/^/    /'
    
    # Clean up temporary files
    rm -f "$csr_file" "$ext_file"
}

generate_my_domain_certificate() {
    log_step "Generating Control Plane MY domain certificate..."
    
    # Build SAN list for MY domain
    local sans=(
        "*.${TP_CP_MY_DOMAIN}"
        "${TP_CP_MY_DOMAIN}"
        "admin.${TP_CP_MY_DOMAIN}"
        "account.${TP_CP_MY_DOMAIN}"
        "apiauth.${TP_CP_MY_DOMAIN}"
        "platform.${TP_CP_MY_DOMAIN}"
        "${TP_SUBSCRIPTION_NAME}.${TP_CP_MY_DOMAIN}"
        "bwce.${TP_CP_MY_DOMAIN}"
        "flogo.${TP_CP_MY_DOMAIN}"
        "localhost"
        "127.0.0.1"
    )
    
    generate_certificate_with_sans "cp-my" "*.${TP_CP_MY_DOMAIN}" "${sans[@]}"
}

generate_tunnel_domain_certificate() {
    log_step "Generating Control Plane TUNNEL domain certificate..."
    
    # Build SAN list for TUNNEL domain
    local sans=(
        "*.${TP_CP_TUNNEL_DOMAIN}"
        "${TP_CP_TUNNEL_DOMAIN}"
        "tunnel.${TP_CP_TUNNEL_DOMAIN}"
        "localhost"
        "127.0.0.1"
    )
    
    generate_certificate_with_sans "cp-tunnel" "*.${TP_CP_TUNNEL_DOMAIN}" "${sans[@]}"
}

generate_combined_certificate() {
    log_step "Generating combined certificate with all SANs..."
    
    # Build comprehensive SAN list covering all domains
    local sans=(
        # MY domain
        "*.${TP_CP_MY_DOMAIN}"
        "${TP_CP_MY_DOMAIN}"
        "admin.${TP_CP_MY_DOMAIN}"
        "account.${TP_CP_MY_DOMAIN}"
        "apiauth.${TP_CP_MY_DOMAIN}"
        "platform.${TP_CP_MY_DOMAIN}"
        "${TP_SUBSCRIPTION_NAME}.${TP_CP_MY_DOMAIN}"
        "bwce.${TP_CP_MY_DOMAIN}"
        "flogo.${TP_CP_MY_DOMAIN}"
        
        # TUNNEL domain
        "*.${TP_CP_TUNNEL_DOMAIN}"
        "${TP_CP_TUNNEL_DOMAIN}"
        "tunnel.${TP_CP_TUNNEL_DOMAIN}"
        
        # Data Plane apps domain
        "*.${TP_DP_DOMAIN}"
        "${TP_DP_DOMAIN}"
        
        # Hybrid proxy (if needed)
        "hybridproxy.${TP_CP_MY_DOMAIN}"
        "*.hybridproxy.${TP_CP_MY_DOMAIN}"
        
        # Additional services
        "${MAILDEV_DOMAIN}"
        "mail.${DNS_SUFFIX}"
        "provisioner.${DNS_SUFFIX}"
        "tekton.${DNS_SUFFIX}"
        
        # Localhost and local IP
        "localhost"
        "127.0.0.1"
    )
    
    generate_certificate_with_sans "combined" "*.${TP_CP_MY_DOMAIN}" "${sans[@]}"
    
    log_info ""
    log_info "Combined certificate covers:"
    log_info "  ✓ Control Plane MY domain and all subdomains"
    log_info "  ✓ Control Plane TUNNEL domain and all subdomains"
    log_info "  ✓ Data Plane apps domain and all subdomains"
    log_info "  ✓ Hybrid proxy domains"
    log_info "  ✓ Mail, Provisioner, and Tekton services"
    log_info "  ✓ localhost and 127.0.0.1"
}

create_kubernetes_secrets() {
    local cert_dir=$1
    
    log_step "Kubernetes Secret Creation Commands"
    log_info ""
    log_info "After creating namespaces, run these commands to create TLS secrets:"
    log_info ""
    
    echo -e "${GREEN}# Create Control Plane namespace (if not exists)${NC}"
    echo "kubectl create namespace ${TP_CP_NAMESPACE}"
    echo ""
    
    echo -e "${GREEN}# Create TLS secret for MY domain${NC}"
    echo "kubectl create secret tls tp-certificate-my \\"
    echo "  --cert=${cert_dir}/cp-my-cert.pem \\"
    echo "  --key=${cert_dir}/cp-my-key.pem \\"
    echo "  -n ${TP_CP_NAMESPACE}"
    echo ""
    
    echo -e "${GREEN}# Create TLS secret for TUNNEL domain${NC}"
    echo "kubectl create secret tls tp-certificate-tunnel \\"
    echo "  --cert=${cert_dir}/cp-tunnel-cert.pem \\"
    echo "  --key=${cert_dir}/cp-tunnel-key.pem \\"
    echo "  -n ${TP_CP_NAMESPACE}"
    echo ""
    
    echo -e "${GREEN}# Create default TLS secret for Traefik ingress (optional)${NC}"
    echo "kubectl create secret tls default-tls-cert \\"
    echo "  --cert=${cert_dir}/combined-cert.pem \\"
    echo "  --key=${cert_dir}/combined-key.pem \\"
    echo "  -n traefik"
    echo ""
    
    log_info "════════════════════════════════════════════════════════════════"
}

create_trust_ca_instructions() {
    local cert_dir=$1
    
    log_step "Trust CA Certificate (Optional - for Browser Access)"
    log_info ""
    log_info "To avoid browser security warnings, add the CA certificate to your system:"
    log_info ""
    
    echo -e "${GREEN}# For macOS:${NC}"
    echo "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${cert_dir}/ca-cert.pem"
    echo ""
    
    echo -e "${GREEN}# For Linux:${NC}"
    echo "sudo cp ${cert_dir}/ca-cert.pem /usr/local/share/ca-certificates/tibco-platform-ca.crt"
    echo "sudo update-ca-certificates"
    echo ""
    
    log_info "════════════════════════════════════════════════════════════════"
}

display_summary() {
    local cert_dir=$1
    
    log_info ""
    log_info "════════════════════════════════════════════════════════════════"
    log_info "Certificate Generation Complete!"
    log_info "════════════════════════════════════════════════════════════════"
    log_info ""
    log_info "Generated Certificates:"
    log_info ""
    log_info "  1. Certificate Authority (CA):"
    log_info "     Certificate: ${cert_dir}/ca-cert.pem"
    log_info "     Private Key: ${cert_dir}/ca-key.pem"
    log_info ""
    log_info "  2. MY Domain (${TP_CP_MY_DOMAIN}):"
    log_info "     Certificate: ${cert_dir}/cp-my-cert.pem"
    log_info "     Private Key: ${cert_dir}/cp-my-key.pem"
    log_info ""
    log_info "  3. TUNNEL Domain (${TP_CP_TUNNEL_DOMAIN}):"
    log_info "     Certificate: ${cert_dir}/cp-tunnel-cert.pem"
    log_info "     Private Key: ${cert_dir}/cp-tunnel-key.pem"
    log_info ""
    log_info "  4. Combined Certificate (All domains):"
    log_info "     Certificate: ${cert_dir}/combined-cert.pem"
    log_info "     Private Key: ${cert_dir}/combined-key.pem"
    log_info ""
    log_warn "⚠️  IMPORTANT SECURITY NOTICE:"
    log_warn "  These are SELF-SIGNED certificates for DEVELOPMENT/TESTING only!"
    log_warn "  For PRODUCTION deployments:"
    log_warn "    1. Obtain certificates from a trusted Certificate Authority (CA)"
    log_warn "    2. Or use cert-manager with Let's Encrypt"
    log_warn "    3. Never use self-signed certificates in production!"
    log_info ""
    log_info "Next Steps:"
    log_info "  1. Create Kubernetes namespaces"
    log_info "  2. Create TLS secrets using the commands shown above"
    log_info "  3. (Optional) Trust the CA certificate on your system"
    log_info "  4. Deploy TIBCO Control Plane"
    log_info "  5. Deploy TIBCO Data Plane"
    log_info ""
    log_info "════════════════════════════════════════════════════════════════"
}

verify_certificates() {
    local cert_dir=$1
    
    log_step "Verifying generated certificates..."
    
    # Verify CA certificate
    if openssl x509 -in "${cert_dir}/ca-cert.pem" -noout -text &>/dev/null; then
        log_info "  ✓ CA certificate is valid"
    else
        log_error "  ✗ CA certificate is invalid"
        exit 1
    fi
    
    # Verify MY domain certificate
    if openssl verify -CAfile "${cert_dir}/ca-cert.pem" "${cert_dir}/cp-my-cert.pem" &>/dev/null; then
        log_info "  ✓ MY domain certificate is valid and trusted by CA"
    else
        log_error "  ✗ MY domain certificate verification failed"
        exit 1
    fi
    
    # Verify TUNNEL domain certificate
    if openssl verify -CAfile "${cert_dir}/ca-cert.pem" "${cert_dir}/cp-tunnel-cert.pem" &>/dev/null; then
        log_info "  ✓ TUNNEL domain certificate is valid and trusted by CA"
    else
        log_error "  ✗ TUNNEL domain certificate verification failed"
        exit 1
    fi
    
    # Verify combined certificate
    if openssl verify -CAfile "${cert_dir}/ca-cert.pem" "${cert_dir}/combined-cert.pem" &>/dev/null; then
        log_info "  ✓ Combined certificate is valid and trusted by CA"
    else
        log_error "  ✗ Combined certificate verification failed"
        exit 1
    fi
    
    log_info ""
    log_info "All certificates verified successfully!"
}

save_certificate_info() {
    local cert_dir=$1
    
    cat > "${cert_dir}/certificate-info.txt" <<EOF
TIBCO Platform Minikube - Certificate Information
Generated: $(date)

══════════════════════════════════════════════════════════════════════════════
Certificate Authority (CA)
══════════════════════════════════════════════════════════════════════════════
Certificate: ${cert_dir}/ca-cert.pem
Private Key: ${cert_dir}/ca-key.pem
Valid For: 10 years

Subject: /C=US/ST=California/L=San Francisco/O=TIBCO Platform/OU=Development/CN=TIBCO Platform Minikube CA

══════════════════════════════════════════════════════════════════════════════
Control Plane MY Domain Certificate
══════════════════════════════════════════════════════════════════════════════
Domain: ${TP_CP_MY_DOMAIN}
Certificate: ${cert_dir}/cp-my-cert.pem
Private Key: ${cert_dir}/cp-my-key.pem
Valid For: ~2 years
Kubernetes Secret Name: tp-certificate-my

Subject Alternative Names (SANs):
  - *.${TP_CP_MY_DOMAIN}
  - ${TP_CP_MY_DOMAIN}
  - account.${TP_CP_MY_DOMAIN}
  - apiauth.${TP_CP_MY_DOMAIN}
  - platform.${TP_CP_MY_DOMAIN}
  - localhost
  - 127.0.0.1

══════════════════════════════════════════════════════════════════════════════
Control Plane TUNNEL Domain Certificate
══════════════════════════════════════════════════════════════════════════════
Domain: ${TP_CP_TUNNEL_DOMAIN}
Certificate: ${cert_dir}/cp-tunnel-cert.pem
Private Key: ${cert_dir}/cp-tunnel-key.pem
Valid For: ~2 years
Kubernetes Secret Name: tp-certificate-tunnel

Subject Alternative Names (SANs):
  - *.${TP_CP_TUNNEL_DOMAIN}
  - ${TP_CP_TUNNEL_DOMAIN}
  - tunnel.${TP_CP_TUNNEL_DOMAIN}
  - localhost
  - 127.0.0.1

══════════════════════════════════════════════════════════════════════════════
Combined Certificate (All Domains)
══════════════════════════════════════════════════════════════════════════════
Certificate: ${cert_dir}/combined-cert.pem
Private Key: ${cert_dir}/combined-key.pem
Valid For: ~2 years
Kubernetes Secret Name: default-tls-cert (for Traefik)

Subject Alternative Names (SANs):
  - *.${TP_CP_MY_DOMAIN} (Control Plane MY)
  - *.${TP_CP_TUNNEL_DOMAIN} (Control Plane TUNNEL)
  - *.${TP_DP_DOMAIN} (Data Plane Apps)
  - hybridproxy.${TP_CP_MY_DOMAIN} (Hybrid Proxy)
  - *.hybridproxy.${TP_CP_MY_DOMAIN}
  - localhost
  - 127.0.0.1

══════════════════════════════════════════════════════════════════════════════
Usage Notes
══════════════════════════════════════════════════════════════════════════════

1. Create Kubernetes TLS Secrets:
   kubectl create secret tls tp-certificate-my --cert=${cert_dir}/cp-my-cert.pem --key=${cert_dir}/cp-my-key.pem -n ${TP_CP_NAMESPACE}
   kubectl create secret tls tp-certificate-tunnel --cert=${cert_dir}/cp-tunnel-cert.pem --key=${cert_dir}/cp-tunnel-key.pem -n ${TP_CP_NAMESPACE}
   kubectl create secret tls default-tls-cert --cert=${cert_dir}/combined-cert.pem --key=${cert_dir}/combined-key.pem -n traefik

2. Trust CA Certificate (to avoid browser warnings):
   macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${cert_dir}/ca-cert.pem
   Linux: sudo cp ${cert_dir}/ca-cert.pem /usr/local/share/ca-certificates/tibco-platform-ca.crt && sudo update-ca-certificates

3. Certificate Rotation:
   Certificates are valid for ~2 years. Regenerate before expiration.

══════════════════════════════════════════════════════════════════════════════
Security Warning
══════════════════════════════════════════════════════════════════════════════

⚠️  These are SELF-SIGNED certificates for DEVELOPMENT/TESTING ONLY!

DO NOT use these certificates in production environments. For production:
  - Obtain certificates from a trusted Certificate Authority (CA)
  - Use cert-manager with Let's Encrypt
  - Use a commercial certificate provider

══════════════════════════════════════════════════════════════════════════════
EOF

    log_info ""
    log_info "Certificate information saved to: ${cert_dir}/certificate-info.txt"
}

################################################################################
# Main Script
################################################################################

main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║  TIBCO Platform - SSL Certificate Generator for Minikube      ║"
    echo "║  Version: 1.0                                                  ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Check prerequisites
    check_prerequisites
    
    # Create certificate directory
    create_cert_directory
    CERT_DIR="$(pwd)/certs"
    
    echo ""
    log_info "Configuration:"
    log_info "  MY Domain:     ${TP_CP_MY_DOMAIN}"
    log_info "  TUNNEL Domain: ${TP_CP_TUNNEL_DOMAIN}"
    log_info "  DP Domain:     ${TP_DP_DOMAIN}"
    log_info "  Output Dir:    ${CERT_DIR}"
    echo ""
    
    # Generate CA certificate
    generate_ca_certificate
    echo ""
    
    # Generate MY domain certificate
    generate_my_domain_certificate
    echo ""
    
    # Generate TUNNEL domain certificate
    generate_tunnel_domain_certificate
    echo ""
    
    # Generate combined certificate
    generate_combined_certificate
    echo ""
    
    # Verify certificates
    verify_certificates "$CERT_DIR"
    echo ""
    
    # Save certificate information
    save_certificate_info "$CERT_DIR"
    
    # Display Kubernetes secret creation commands
    create_kubernetes_secrets "$CERT_DIR"
    echo ""
    
    # Display CA trust instructions
    create_trust_ca_instructions "$CERT_DIR"
    echo ""
    
    # Display summary
    display_summary "$CERT_DIR"
    
    # Update environment variables
    log_info "Updating environment variables..."
    export TP_TLS_CERT_MY="${CERT_DIR}/cp-my-cert.pem"
    export TP_TLS_KEY_MY="${CERT_DIR}/cp-my-key.pem"
    export TP_TLS_CERT_TUNNEL="${CERT_DIR}/cp-tunnel-cert.pem"
    export TP_TLS_KEY_TUNNEL="${CERT_DIR}/cp-tunnel-key.pem"
    export TP_TLS_CERT_COMBINED="${CERT_DIR}/combined-cert.pem"
    export TP_TLS_KEY_COMBINED="${CERT_DIR}/combined-key.pem"
    
    log_info "Certificate paths exported to environment variables!"
    echo ""
}

# Run main function
main "$@"
