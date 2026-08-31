#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

REPO="${LIGHTR_REPO:-nigelbasa/lightr}"
VERSION="${LIGHTR_VERSION:-latest}"
INSTALL_DIR="${LIGHTR_INSTALL_DIR:-/usr/local/bin}"
CONFIG_PATH="${LIGHTR_CONFIG_PATH:-/etc/lightr/config.yaml}"
DATA_DIR="${LIGHTR_DATA_DIR:-/var/lib/lightr}"
LOG_DIR="${LIGHTR_LOG_DIR:-/var/log/lightr}"
SERVICE_PATH="${LIGHTR_SERVICE_PATH:-/etc/systemd/system/lightr.service}"
MAIL_HOSTNAME_OVERRIDE="${LIGHTR_MAIL_HOSTNAME:-}"

DOMAIN=""
HOSTNAME_OVERRIDE=""
START_SERVICE=0
ENABLE_SERVICE=1
SKIP_INIT=0
FORCE_INIT=0

usage() {
  cat <<'EOF'
Lightr installer

Usage:
  install.sh [domain]
  install.sh --domain example.com [--hostname mail.example.com] [--mail-hostname mail.example.com] [--start]

Options:
  --domain VALUE      Base mail domain. Initializes hostname as mail.VALUE.
  --hostname VALUE    Override the hostname written into the config.
  --mail-hostname VALUE
                      Public hostname to suggest for the first managed domain.
                      Defaults to the configured runtime hostname.
  --version VALUE     Release version to install, e.g. 0.1.0 or v0.1.0.
                      Defaults to the latest GitHub release.
  --start             Start the systemd service after installation.
  --skip-init         Install the binary and service without generating config.
  --force-init        Overwrite an existing config during init.
  --no-enable         Do not enable the systemd service.
  --help              Show this help text.

Environment overrides:
  LIGHTR_REPO         GitHub repository slug. Default: nigelbasa/lightr
  LIGHTR_VERSION      Same as --version
  LIGHTR_INSTALL_DIR  Default: /usr/local/bin
  LIGHTR_CONFIG_PATH  Default: /etc/lightr/config.yaml
  LIGHTR_DATA_DIR     Default: /var/lib/lightr
  LIGHTR_LOG_DIR      Default: /var/log/lightr
  LIGHTR_MAIL_HOSTNAME
                      Same as --mail-hostname

Examples:
  curl -fsSL https://lightr.nigelbasa.tech/install.sh | sudo bash -s -- example.com
  curl -fsSL https://lightr.nigelbasa.tech/install.sh | sudo bash -s -- --domain example.com --mail-hostname mail.example.com --start
EOF
}

log() {
  printf '[lightr] %s\n' "$*"
}

warn() {
  printf '[lightr] warning: %s\n' "$*" >&2
}

die() {
  printf '[lightr] error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

download() {
  local url="$1"
  local dest="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
    return
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url"
    return
  fi
  die "curl or wget is required to download release assets"
}

normalize_version() {
  VERSION="${VERSION#v}"
}

resolve_arch() {
  case "$(uname -m)" in
    x86_64|amd64)
      printf 'amd64\n'
      ;;
    aarch64|arm64)
      printf 'arm64\n'
      ;;
    *)
      die "unsupported architecture: $(uname -m)"
      ;;
  esac
}

default_hostname() {
  if [ -n "$HOSTNAME_OVERRIDE" ]; then
    printf '%s\n' "$HOSTNAME_OVERRIDE"
    return
  fi
  if [ -n "$DOMAIN" ]; then
    printf 'mail.%s\n' "$DOMAIN"
    return
  fi
  if command -v hostname >/dev/null 2>&1; then
    local detected
    detected="$(hostname -f 2>/dev/null || true)"
    if [ -n "$detected" ] && [ "$detected" != "localhost" ]; then
      printf '%s\n' "$detected"
      return
    fi
  fi
  printf 'mail.example.com\n'
}

default_mail_hostname() {
  if [ -n "$MAIL_HOSTNAME_OVERRIDE" ]; then
    printf '%s\n' "$MAIL_HOSTNAME_OVERRIDE"
    return
  fi
  printf '%s\n' "$HOSTNAME_VALUE"
}

ensure_linux_systemd() {
  [ "$(uname -s)" = "Linux" ] || die "this installer currently supports Linux only"
  [ -d /run/systemd/system ] || die "systemd is required for this installer"
}

ensure_root() {
  [ "$(id -u)" -eq 0 ] || die "run this installer as root"
}

create_service_user() {
  if ! getent group lightr >/dev/null 2>&1; then
    log "creating lightr group"
    groupadd --system lightr
  fi

  if ! getent passwd lightr >/dev/null 2>&1; then
    log "creating lightr user"
    useradd --system --gid lightr --home-dir "$DATA_DIR" \
      --shell /usr/sbin/nologin --comment "Lightr Mail Server" lightr
  fi
}

prepare_directories() {
  log "preparing directories"
  install -d -m 0750 -o root -g lightr "$(dirname "$CONFIG_PATH")"
  install -d -m 0755 -o lightr -g lightr "$DATA_DIR"
  install -d -m 0755 -o lightr -g lightr "$LOG_DIR"
}

install_binary() {
  local arch="$1"
  local tmpdir="$2"
  local asset="lightr-linux-${arch}"
  local url

  if [ "$VERSION" = "latest" ]; then
    url="https://github.com/${REPO}/releases/latest/download/${asset}"
  else
    normalize_version
    url="https://github.com/${REPO}/releases/download/v${VERSION}/${asset}"
  fi

  log "downloading ${url}"
  download "$url" "${tmpdir}/lightr"

  log "installing binary to ${INSTALL_DIR}/lightr"
  install -d -m 0755 "$INSTALL_DIR"
  install -m 0755 "${tmpdir}/lightr" "${INSTALL_DIR}/lightr"
}

write_service() {
  local binary_path="${INSTALL_DIR}/lightr"

  log "writing systemd unit to ${SERVICE_PATH}"
  cat >"$SERVICE_PATH" <<EOF
[Unit]
Description=Lightr Lightweight Email Server
Documentation=https://github.com/nigelbasa/lightr
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=lightr
Group=lightr
WorkingDirectory=${DATA_DIR}
ExecStart=${binary_path} --config ${CONFIG_PATH} serve
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "$SERVICE_PATH"
}

initialize_config() {
  local binary_path="${INSTALL_DIR}/lightr"
  local hostname_value="$1"
  local init_args=(
    init
    --config "$CONFIG_PATH"
    --data-dir "$DATA_DIR"
    --hostname "$hostname_value"
  )

  if [ -f "$CONFIG_PATH" ] && [ "$FORCE_INIT" -ne 1 ]; then
    log "config already exists at ${CONFIG_PATH}; leaving it in place"
  else
    if [ "$FORCE_INIT" -eq 1 ]; then
      init_args+=(--force)
    fi
    log "initializing config at ${CONFIG_PATH}"
    "$binary_path" "${init_args[@]}"
  fi

  if [ -f "$CONFIG_PATH" ]; then
    chown root:lightr "$CONFIG_PATH"
    chmod 0640 "$CONFIG_PATH"
  fi
  chown -R lightr:lightr "$DATA_DIR"
  chown -R lightr:lightr "$LOG_DIR"
}

enable_service() {
  systemctl daemon-reload
  if [ "$ENABLE_SERVICE" -eq 1 ]; then
    log "enabling lightr.service"
    systemctl enable lightr.service >/dev/null
  fi
}

start_service_if_requested() {
  local binary_path="${INSTALL_DIR}/lightr"

  if [ "$START_SERVICE" -ne 1 ]; then
    return
  fi

  log "validating config before start"
  "$binary_path" --config "$CONFIG_PATH" config validate >/dev/null

  log "starting lightr.service"
  systemctl restart lightr.service
}

print_summary() {
  local hostname_value="$1"
  local mail_hostname_value="$2"

  cat <<EOF

Lightr is installed.

Binary:
  ${INSTALL_DIR}/lightr

Config:
  ${CONFIG_PATH}

Data:
  ${DATA_DIR}

Service:
  ${SERVICE_PATH}

Initialized hostname:
  ${hostname_value}

Suggested first domain mail hostname:
  ${mail_hostname_value}

Next steps:
  1. Review the config:
     sudo nano ${CONFIG_PATH}
  2. Validate it:
     sudo ${INSTALL_DIR}/lightr config validate
  3. Start the service:
     sudo systemctl start lightr
  4. Check status:
     sudo systemctl status lightr
  5. Tail logs:
     sudo journalctl -u lightr -f
EOF

  if [ -n "$DOMAIN" ]; then
    cat <<EOF

Suggested first tenant setup:
  sudo ${INSTALL_DIR}/lightr domain create --name ${DOMAIN} --mail-hostname ${mail_hostname_value} --spam-policy junk
  sudo ${INSTALL_DIR}/lightr domain dns ${DOMAIN}
  sudo ${INSTALL_DIR}/lightr account create --domain ${DOMAIN} --email ops@${DOMAIN} --password CHANGE_ME

Reminder:
  The managed domain is ${DOMAIN}, while ${mail_hostname_value} is the public mail host
  you should line up across MX, SPF, TLS, and PTR where appropriate.
EOF
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --domain)
      [ "$#" -ge 2 ] || die "--domain requires a value"
      DOMAIN="$2"
      shift 2
      ;;
    --hostname)
      [ "$#" -ge 2 ] || die "--hostname requires a value"
      HOSTNAME_OVERRIDE="$2"
      shift 2
      ;;
    --mail-hostname)
      [ "$#" -ge 2 ] || die "--mail-hostname requires a value"
      MAIL_HOSTNAME_OVERRIDE="$2"
      shift 2
      ;;
    --version)
      [ "$#" -ge 2 ] || die "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --start)
      START_SERVICE=1
      shift
      ;;
    --skip-init)
      SKIP_INIT=1
      shift
      ;;
    --force-init)
      FORCE_INIT=1
      shift
      ;;
    --no-enable)
      ENABLE_SERVICE=0
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --*)
      die "unknown option: $1"
      ;;
    *)
      if [ -n "$DOMAIN" ]; then
        die "unexpected extra argument: $1"
      fi
      DOMAIN="$1"
      shift
      ;;
  esac
done

ensure_root
ensure_linux_systemd
need_cmd install
need_cmd getent
need_cmd useradd
need_cmd groupadd
need_cmd systemctl
need_cmd uname

ARCH="$(resolve_arch)"
HOSTNAME_VALUE="$(default_hostname)"
MAIL_HOSTNAME_VALUE="$(default_mail_hostname)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

log "install target: linux/${ARCH}"
install_binary "$ARCH" "$TMPDIR"
create_service_user
prepare_directories
write_service

if [ "$SKIP_INIT" -ne 1 ]; then
  initialize_config "$HOSTNAME_VALUE"
else
  log "skipping init as requested"
fi

enable_service
start_service_if_requested
print_summary "$HOSTNAME_VALUE" "$MAIL_HOSTNAME_VALUE"
