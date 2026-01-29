#!/bin/bash
# Lightr Quick Start Script
# Run with: sudo ./quickstart.sh

set -e

DOMAIN="${1:-yourdomain.com}"
VPS_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_VPS_IP")

echo "============================================"
echo "  Lightr Email Server - Quick Start"
echo "============================================"
echo ""
echo "Domain: $DOMAIN"
echo "VPS IP: $VPS_IP"
echo ""

# Check if running as root for port 25
if [ "$EUID" -ne 0 ] && [ -z "$SKIP_ROOT_CHECK" ]; then
    echo "⚠️  Not running as root. Port 25 requires root."
    echo "   Run with: sudo $0 $DOMAIN"
    echo "   Or use: SKIP_ROOT_CHECK=1 $0 $DOMAIN (uses port 2525)"
    echo ""
    USE_ALT_PORTS=1
fi

# Create directories
echo "📁 Creating directories..."
mkdir -p data logs config

# Check DNS
echo ""
echo "🔍 Checking DNS records..."
echo ""

# Check MX record
MX_RECORD=$(dig +short MX "$DOMAIN" 2>/dev/null || echo "")
if [ -n "$MX_RECORD" ]; then
    echo "✅ MX Record: $MX_RECORD"
else
    echo "❌ No MX record found for $DOMAIN"
    echo ""
    echo "Add this DNS record:"
    echo "  $DOMAIN.  IN  MX  10 mail.$DOMAIN."
    echo ""
fi

# Check A record for mail subdomain
MAIL_A=$(dig +short A "mail.$DOMAIN" 2>/dev/null || echo "")
if [ -n "$MAIL_A" ]; then
    echo "✅ A Record (mail.$DOMAIN): $MAIL_A"
else
    echo "❌ No A record for mail.$DOMAIN"
    echo ""
    echo "Add this DNS record:"
    echo "  mail.$DOMAIN.  IN  A  $VPS_IP"
    echo ""
fi

# Check SPF record
SPF_RECORD=$(dig +short TXT "$DOMAIN" 2>/dev/null | grep "v=spf1" || echo "")
if [ -n "$SPF_RECORD" ]; then
    echo "✅ SPF Record: $SPF_RECORD"
else
    echo "⚠️  No SPF record (optional but recommended)"
    echo ""
    echo "Add this DNS record:"
    echo "  $DOMAIN.  IN  TXT  \"v=spf1 ip4:$VPS_IP -all\""
    echo ""
fi

# Check DKIM
DKIM_RECORD=$(dig +short TXT "default._domainkey.$DOMAIN" 2>/dev/null || echo "")
if [ -n "$DKIM_RECORD" ]; then
    echo "✅ DKIM Record found"
else
    echo "ℹ️  No DKIM record (can add later)"
fi

# Check DMARC
DMARC_RECORD=$(dig +short TXT "_dmarc.$DOMAIN" 2>/dev/null || echo "")
if [ -n "$DMARC_RECORD" ]; then
    echo "✅ DMARC Record: $DMARC_RECORD"
else
    echo "ℹ️  No DMARC record (can add later)"
fi

echo ""
echo "============================================"
echo "  Minimum Required DNS Records"
echo "============================================"
echo ""
echo "1. MX Record (REQUIRED for receiving):"
echo "   $DOMAIN.  IN  MX  10 mail.$DOMAIN."
echo ""
echo "2. A Record (REQUIRED):"
echo "   mail.$DOMAIN.  IN  A  $VPS_IP"
echo ""
echo "3. SPF Record (Recommended):"
echo "   $DOMAIN.  IN  TXT  \"v=spf1 ip4:$VPS_IP -all\""
echo ""
echo "============================================"
echo ""

# Generate config
echo "📝 Generating configuration..."
cat > config/config.yaml << EOF
server:
  hostname: mail.$DOMAIN
  bind_address: 0.0.0.0

smtp:
  enabled: true
  port: ${USE_ALT_PORTS:+2525}${USE_ALT_PORTS:-25}
  max_message_size: 26214400

submission:
  enabled: true
  port: ${USE_ALT_PORTS:+2587}${USE_ALT_PORTS:-587}
  require_auth: true

imap:
  enabled: true
  port: ${USE_ALT_PORTS:+2143}${USE_ALT_PORTS:-143}

database:
  path: ./data/lightr.db

outbound:
  enabled: true
  dkim:
    enabled: false
  rate_limit:
    per_minute: 10
    per_hour: 100

inbound:
  spf:
    enabled: true
    soft_fail_action: accept
  dkim:
    enabled: true
    fail_action: accept
  dmarc:
    enabled: true
    fail_action: accept

spam:
  enabled: true
  threshold: 5.0

api:
  enabled: true
  port: 8080
  admin_key: "$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p)"

logging:
  level: info
  file: ./logs/lightr.log

domains:
  - name: $DOMAIN
    enabled: true
EOF

echo "✅ Configuration saved to config/config.yaml"
echo ""

# Check firewall
echo "🔥 Checking firewall ports..."
if command -v ufw &> /dev/null; then
    echo "UFW detected. Required ports:"
    echo "  sudo ufw allow 25/tcp    # SMTP"
    echo "  sudo ufw allow 587/tcp   # Submission"
    echo "  sudo ufw allow 143/tcp   # IMAP"
    echo "  sudo ufw allow 993/tcp   # IMAPS"
    echo "  sudo ufw allow 8080/tcp  # API"
elif command -v firewall-cmd &> /dev/null; then
    echo "firewalld detected. Required ports:"
    echo "  sudo firewall-cmd --add-port=25/tcp --permanent"
    echo "  sudo firewall-cmd --add-port=587/tcp --permanent"
    echo "  sudo firewall-cmd --add-port=143/tcp --permanent"
    echo "  sudo firewall-cmd --add-port=993/tcp --permanent"
    echo "  sudo firewall-cmd --reload"
fi
echo ""

# Start instructions
echo "============================================"
echo "  Ready to Start!"
echo "============================================"
echo ""
if [ -n "$USE_ALT_PORTS" ]; then
    echo "Using alternate ports (no root required):"
    echo "  SMTP: 2525, Submission: 2587, IMAP: 2143"
    echo ""
fi
echo "To start the server:"
echo "  ./lightr serve --config config/config.yaml"
echo ""
echo "To test receiving email:"
echo "  Send an email to test@$DOMAIN"
echo ""
echo "⚠️  Note: Without DKIM/DMARC, outgoing emails may"
echo "   be marked as spam by recipients."
echo ""
echo "To add DKIM later, run:"
echo "  ./lightr dkim generate --domain $DOMAIN"
echo ""
