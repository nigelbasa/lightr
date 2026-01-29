#!/bin/bash
# Pre-removal script for lightr

set -e

# Stop service if running
if systemctl is-active --quiet lightr; then
    systemctl stop lightr
fi

# Disable service
if systemctl is-enabled --quiet lightr 2>/dev/null; then
    systemctl disable lightr
fi

echo "Lightr service stopped and disabled."
echo "Note: Data in /var/lib/lightr and config in /etc/lightr are preserved."
