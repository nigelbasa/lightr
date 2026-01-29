#!/bin/bash
# Post-installation script for lightr

set -e

LIGHTR_USER="lightr"
LIGHTR_GROUP="lightr"
CONFIG_DIR="/etc/lightr"
DATA_DIR="/var/lib/lightr"
LOG_DIR="/var/log/lightr"

# Create system user and group
if ! getent group "$LIGHTR_GROUP" > /dev/null 2>&1; then
    groupadd --system "$LIGHTR_GROUP"
fi

if ! getent passwd "$LIGHTR_USER" > /dev/null 2>&1; then
    useradd --system \
        --gid "$LIGHTR_GROUP" \
        --home-dir "$DATA_DIR" \
        --shell /usr/sbin/nologin \
        --comment "Lightr Email Server" \
        "$LIGHTR_USER"
fi

# Create directories
mkdir -p "$CONFIG_DIR"
mkdir -p "$CONFIG_DIR/certs"
mkdir -p "$DATA_DIR"
mkdir -p "$DATA_DIR/blobs"
mkdir -p "$DATA_DIR/keys"
mkdir -p "$LOG_DIR"

# Set ownership
chown -R "$LIGHTR_USER:$LIGHTR_GROUP" "$DATA_DIR"
chown -R "$LIGHTR_USER:$LIGHTR_GROUP" "$LOG_DIR"
chown root:$LIGHTR_GROUP "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR/certs"

# Install default config if not exists
if [ ! -f "$CONFIG_DIR/lightr.yaml" ]; then
    if [ -f "$CONFIG_DIR/lightr.yaml.example" ]; then
        cp "$CONFIG_DIR/lightr.yaml.example" "$CONFIG_DIR/lightr.yaml"
    fi
    chown root:$LIGHTR_GROUP "$CONFIG_DIR/lightr.yaml"
    chmod 640 "$CONFIG_DIR/lightr.yaml"
fi

# Reload systemd
systemctl daemon-reload

echo ""
echo "Lightr installed successfully!"
echo ""
echo "Next steps:"
echo "  1. Edit /etc/lightr/lightr.yaml"
echo "  2. Initialize: sudo -u lightr lightr init --config /etc/lightr/lightr.yaml"
echo "  3. Start service: sudo systemctl start lightr"
echo "  4. Enable on boot: sudo systemctl enable lightr"
echo ""
