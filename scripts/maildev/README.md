# MailDev - Development Mail Server for Minikube

MailDev is a simple SMTP server for development and testing. It captures all emails and displays them in a web interface, perfect for testing TIBCO Platform email notifications without sending real emails.

## Features

- **SMTP Server**: Captures all outgoing emails on port 1025
- **Web UI**: View captured emails at https://mail.lvh.me
- **Lightweight**: Minimal resource usage (32Mi memory, 25m CPU)
- **No Configuration**: Works out of the box

## Prerequisites

1. Minikube profile "tp" running
2. Minikube tunnel active
3. Traefik ingress controller installed
4. TLS certificates generated

## Deployment

### Quick Deploy

```bash
# Deploy MailDev
kubectl apply -f scripts/maildev/maildev-deploy.yaml

# Create TLS secret for the mail domain
kubectl create secret tls maildev-tls-cert \
  --cert=certs/combined-cert.pem \
  --key=certs/combined-key.pem \
  -n tibco-ext

# Verify deployment
kubectl get pods -n tibco-ext
kubectl get ingress -n tibco-ext
```

### Access MailDev

Once deployed, access MailDev at:
- **Web UI**: https://mail.lvh.me
- **SMTP Server**: development-mailserver.tibco-ext.svc.cluster.local:1025

## Configure TIBCO Platform to Use MailDev

When deploying the Control Plane, configure the mail server settings:

```yaml
# In your Control Plane values file
email:
  smtp:
    host: development-mailserver.tibco-ext.svc.cluster.local
    port: 1025
    from: noreply@lvh.me
    # No authentication needed for MailDev
    username: ""
    password: ""
    tls:
      enabled: false
```

Or via Helm install command:

```bash
helm install tibco-platform ... \
  --set email.smtp.host=development-mailserver.tibco-ext.svc.cluster.local \
  --set email.smtp.port=1025 \
  --set email.smtp.from=noreply@lvh.me \
  --set email.smtp.tls.enabled=false
```

## Verify Email Capture

1. Trigger an email from TIBCO Platform (e.g., user invitation, password reset)
2. Open https://mail.lvh.me
3. View the captured email in the web interface

## Troubleshooting

### Cannot access mail.lvh.me

```bash
# Check if maildev pod is running
kubectl get pods -n tibco-ext

# Check if ingress is created
kubectl get ingress -n tibco-ext

# Check if TLS secret exists
kubectl get secret maildev-tls-cert -n tibco-ext

# View maildev logs
kubectl logs -n tibco-ext -l app=development-mailserver
```

### Emails not appearing

```bash
# Check SMTP connectivity from within cluster
kubectl run -it --rm debug --image=busybox --restart=Never -- \
  telnet development-mailserver.tibco-ext.svc.cluster.local 1025

# Check maildev logs
kubectl logs -n tibco-ext -l app=development-mailserver -f
```

## Cleanup

```bash
# Remove MailDev
kubectl delete -f scripts/maildev/maildev-deploy.yaml

# Remove TLS secret
kubectl delete secret maildev-tls-cert -n tibco-ext
```

## Alternative: Using NodePort (without Ingress)

If you prefer to access MailDev via NodePort instead of Ingress:

```bash
# Change Service type to NodePort
kubectl patch svc development-mailserver -n tibco-ext -p '{"spec": {"type": "NodePort"}}'

# Get the NodePort
MAILDEV_PORT=$(kubectl get svc development-mailserver -n tibco-ext -o jsonpath='{.spec.ports[?(@.name=="http")].nodePort}')

# Access via NodePort
echo "MailDev UI: http://$(minikube ip -p tp):${MAILDEV_PORT}"
```

## Production Considerations

⚠️ **WARNING**: MailDev is for development/testing ONLY!

For production environments:
- Use a real SMTP server (SendGrid, AWS SES, etc.)
- Configure proper authentication
- Enable TLS/SSL
- Set up SPF/DKIM records
- Monitor email delivery rates
