#!/usr/bin/env bash
# sparky-manager installer — original work, written from scratch for this project.
#
# Installs sparky-manager (FastAPI panel + stock Xray-core + stock sing-box +
# native WireGuard + OpenVPN + OpenConnect (ocserv) + AmneziaWG + native
# IKEv2 via strongSwan) on Ubuntu 22.04/24.04/26.04 or Debian 12/13.
#
# Domain-agnostic: works with a bare server IP and NO domain. The default
# first pair is VLESS+Reality (TCP 443) + Hysteria2 (UDP 443) + WireGuard
# (UDP 51820) — none of them needs a domain or a certificate. When no
# domain is given, the panel serves a self-signed certificate (the browser
# will warn; the login box prints the fingerprint so you can check it).
# If a domain is supplied, it is recorded for the panel; Let's Encrypt
# certificates are an option inside the panel settings, never a
# requirement at install time.
#
# Usage:
#   sudo bash install.sh [--yes] [--port PORT] [--web-path PATH] [--domain example.com]
#                        [--reality-sni www.microsoft.com]
#                        [--admin-password 'secret']
#   curl -Ls https://raw.githubusercontent.com/SPARKY-CR/sparky-manager/main/install.sh | sudo bash
#   sudo bash install.sh --uninstall
#
# The repo URL above needs the GitHub repo named SPARKY-CR/sparky-manager
# (renamed from Zed-panel). Idempotent: safe to re-run; existing keys
# and the admin password are reused instead of regenerated.
#
# The panel port is randomised on a fresh install (like other panels),
# re-used on re-install, and always printed before the install proceeds
# (prompt, summary and login box); --yes accepts it, --port fixes it.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults (all printed before proceeding; overridable with flags)
# ---------------------------------------------------------------------------
REPO_URL="https://github.com/SPARKY-CR/sparky-manager.git"
PANEL_PORT=""        # empty = not given; resolved below (random on fresh install)
PORT_GIVEN=0         # 1 when --port is passed
WEB_PATH=""          # empty = not given; resolved below (random on fresh install)
WEB_PATH_GIVEN=0      # 1 when --web-path is passed
DOMAIN=""
REALITY_SNI="www.microsoft.com"
ADMIN_PASSWORD=""
YES=0
UNINSTALL=0

XRAY_CONFIG="/usr/local/etc/xray/config.json"
SINGBOX_CONFIG="/etc/sing-box/config.json"
WG_CONFIG="/etc/wireguard/wg0.conf"
LOGIN_FILE="/root/sparky-manager-login.txt"

PANEL_VERSION="1.2.0"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# Log lines go to stderr so that command substitutions capturing a
# function's stdout (e.g. the release tag from download_core) stay clean.
info()  { printf '[sparky-manager] %s\n' "$*" >&2; }
warn()  { printf '[sparky-manager] WARNING: %s\n' "$*" >&2; }
die()   { printf '[sparky-manager] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: install.sh [OPTIONS]

Options:
  --yes                     Accept all defaults, ask nothing.
  --port PORT               Panel port (default: random free port
                            10000-60000 on a fresh install; the
                            previous port is reused on re-install).
  --web-path PATH           Secret web path (default: random 12-char
                            path on a fresh install; the previous path
                            is reused on re-install; the panel only
                            answers under /<path>).
  --domain DOMAIN           Domain for the panel (default: none — bare IP,
                            self-signed panel certificate).
  --reality-sni SNI         SNI for VLESS+Reality (default: www.microsoft.com).
  --admin-password PASS     Admin password (default: generated once and
                            printed in the login box).
  --uninstall               Stop services, back up data, remove sparky-manager.
  --help                    Show this help.
EOF
}

# sq VALUE — print VALUE single-quoted for safe storage in an env file.
sq() { printf "'%s'" "${1//\'/\'\\\'\'}"; }

# ask VAR LABEL DEFAULT — prompt on /dev/tty when available; otherwise keep
# the default. Skipped entirely with --yes. Never reads from stdin, because
# stdin may be the install script itself when piped from curl.
ask() {
    local var_name="$1" label="$2" default_value="$3" reply=""
    if [ "$YES" -eq 1 ]; then
        return 0
    fi
    if [ -e /dev/tty ]; then
        printf '%s [%s]: ' "$label" "$default_value" > /dev/tty
        IFS= read -r reply < /dev/tty || reply=""
        if [ -n "$reply" ]; then
            printf -v "$var_name" '%s' "$reply"
        fi
    else
        info "No terminal for prompts; using default $label=$default_value"
    fi
}

# ask_secret VAR LABEL — same as ask, but without echo (for passwords).
ask_secret() {
    local var_name="$1" label="$2" reply=""
    if [ "$YES" -eq 1 ]; then
        return 0
    fi
    if [ -e /dev/tty ]; then
        printf '%s (empty = generate one): ' "$label" > /dev/tty
        IFS= read -rs reply < /dev/tty || reply=""
        printf '\n' > /dev/tty
        if [ -n "$reply" ]; then
            printf -v "$var_name" '%s' "$reply"
        fi
    else
        info "No terminal for prompts; an admin password will be generated."
    fi
}

# pick_random_port — choose a free TCP port in 10000-60000 for the panel
# (like other panels: randomised on a FRESH install, printed in the login
# box and saved to panel.env; a re-install reuses the existing port).
# Probes with a bash /dev/tcp connect: refused = free, connected = busy.
pick_random_port() {
    local port tries=0
    while [ "$tries" -lt 50 ]; do
        tries=$((tries + 1))
        if command -v shuf >/dev/null 2>&1; then
            port="$(shuf -i 10000-60000 -n 1)"
        else
            port=$((10000 + RANDOM % 50001))
        fi
        if (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
            continue
        fi
        printf '%s' "$port"
        return 0
    done
    die "Could not find a free panel port after 50 tries."
}

# pick_random_web_path — a random 12-char [a-z0-9] segment for the
# secret panel web path (like 3X-UI's webBasePath). The panel only
# answers under /<path>; without it the root returns 404.
pick_random_web_path() {
    # NOTE: `|| true` is load-bearing. `tr` reads an infinite stream;
    # `head` exits after 12 bytes and `tr` then dies with SIGPIPE
    # (exit 141). With `set -euo pipefail` that would kill the whole
    # installer silently — exactly what happened on the server (it
    # stopped right after "Reusing existing panel port", no error).
    tr -dc 'a-z0-9' < /dev/urandom | head -c 12 || true
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y)           YES=1; shift ;;
        --uninstall)        UNINSTALL=1; shift ;;
        --help|-h)          usage; exit 0 ;;
        --port)             PANEL_PORT="$2"; PORT_GIVEN=1; shift 2 ;;
        --port=*)           PANEL_PORT="${1#--port=}"; PORT_GIVEN=1; shift ;;
        --web-path)         WEB_PATH="$2"; WEB_PATH_GIVEN=1; shift 2 ;;
        --web-path=*)       WEB_PATH="${1#--web-path=}"; WEB_PATH_GIVEN=1; shift ;;
        --domain)           DOMAIN="$2"; shift 2 ;;
        --domain=*)         DOMAIN="${1#--domain=}"; shift ;;
        --reality-sni)      REALITY_SNI="$2"; shift 2 ;;
        --reality-sni=*)    REALITY_SNI="${1#--reality-sni=}"; shift ;;
        --admin-password)   ADMIN_PASSWORD="$2"; shift 2 ;;
        --admin-password=*) ADMIN_PASSWORD="${1#--admin-password=}"; shift ;;
        *)                  die "Unknown option: $1 (see --help)" ;;
    esac
done

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
uninstall_panel() {
    local stamp backup_file
    stamp="$(date +%F-%H%M%S)"
    backup_file="/root/sparky-manager-backup-${stamp}.tar.gz"
    info "Backing up data and configs to ${backup_file} ..."
    local -a paths=()
    [ -d /opt/sparky-manager/data ] && paths+=("/opt/sparky-manager/data")
    [ -f /usr/local/etc/xray/config.json ] && paths+=("/usr/local/etc/xray/config.json")
    [ -f /etc/sing-box/config.json ] && paths+=("/etc/sing-box/config.json")
    [ -f /opt/sparky-manager/versions.env ] && paths+=("/opt/sparky-manager/versions.env")
    if [ "${#paths[@]}" -gt 0 ]; then
        tar -czf "$backup_file" "${paths[@]}" 2>/dev/null || \
            warn "Backup tarball may be incomplete; check ${backup_file}"
    else
        warn "Nothing to back up (no data or configs found)."
    fi

    info "Stopping services ..."
    systemctl stop sparky-manager xray sing-box 2>/dev/null || true
    systemctl disable sparky-manager xray sing-box 2>/dev/null || true
    if [ -f /etc/wireguard/wg0.conf ]; then
        wg-quick down wg0 2>/dev/null || true
    fi

    info "Removing files, units and binaries ..."
    rm -f /etc/systemd/system/sparky-manager.service \
          /etc/systemd/system/xray.service \
          /etc/systemd/system/sing-box.service
    rm -f /etc/sudoers.d/sparky-manager /etc/sudoers.d/vpn-panel
    systemctl daemon-reload || true
    rm -rf /opt/sparky-manager /usr/local/etc/xray /etc/sing-box
    rm -f /etc/wireguard/wg0.conf
    rm -f /usr/local/bin/xray /usr/local/bin/sing-box /usr/local/bin/sparky-manager
    if id sparky-manager >/dev/null 2>&1; then
        userdel sparky-manager 2>/dev/null || warn "Could not remove user sparky-manager."
    fi
    info "sparky-manager uninstalled. Backup kept at: ${backup_file}"
    info "The login file ${LOGIN_FILE} was left in place on purpose."
}

if [ "$UNINSTALL" -eq 1 ]; then
    [ "$(id -u)" -eq 0 ] || die "Uninstall must run as root (use sudo)."
    uninstall_panel
    exit 0
fi

# ---------------------------------------------------------------------------
# Preconditions: root, supported OS, supported CPU
# ---------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "This installer must run as root (use sudo)."

if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
else
    die "Cannot detect the OS (/etc/os-release missing)."
fi

case "${ID:-unknown}-${VERSION_ID:-unknown}" in
    ubuntu-22.04|ubuntu-24.04|ubuntu-26.04|debian-12|debian-13)
        info "Detected supported OS: ${ID} ${VERSION_ID}"
        ;;
    *)
        die "Unsupported OS: ${ID:-unknown} ${VERSION_ID:-unknown}. Only Ubuntu 22.04/24.04/26.04 and Debian 12/13 are supported."
        ;;
esac

case "$(uname -m)" in
    x86_64)
        ARCH="amd64"
        XRAY_ASSET_RE='^Xray-linux-64\.zip$'
        ;;
    aarch64|arm64)
        ARCH="arm64"
        XRAY_ASSET_RE='^Xray-linux-arm64-v8a\.zip$'
        ;;
    *)
        die "Unsupported CPU architecture: $(uname -m). Only x86_64 and aarch64 are supported."
        ;;
esac
SINGBOX_ASSET_RE="^sing-box-.*-linux-${ARCH}\\.tar\\.gz$"

for cmd in curl python3 openssl tar; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required tool missing: $cmd"
done

# ---------------------------------------------------------------------------
# Migration from the previous name (vpn-panel -> sparky-manager).
# A server already running vpn-panel keeps its database, keys,
# certificate and panel URL: stop the old service first (never copy a
# live SQLite DB), copy the data over, translate the old VPN_PANEL_*
# env keys to SPARKY_*, then remove the old unit and CLI wrapper. A
# re-run finds the new panel.env already in place and skips the copy.
# The old /opt/vpn-panel directory is left in place as a backup;
# only the service is removed.
# ---------------------------------------------------------------------------
if [ -d /opt/vpn-panel ]; then
    info "Found a previous vpn-panel install; migrating to sparky-manager ..."
    mkdir -p /opt/sparky-manager/app /opt/sparky-manager/data /opt/sparky-manager/certs
    if ! id sparky-manager >/dev/null 2>&1; then
        useradd --system --no-create-home --home-dir /opt/sparky-manager \
                --shell /usr/sbin/nologin sparky-manager
    fi
    systemctl stop vpn-panel 2>/dev/null || true
    systemctl disable vpn-panel 2>/dev/null || true
    if [ ! -f /opt/sparky-manager/data/panel.env ] && [ -d /opt/vpn-panel/data ]; then
        cp -a /opt/vpn-panel/data/. /opt/sparky-manager/data/
        if [ -f /opt/sparky-manager/data/panel.env ]; then
            sed -i 's/^VPN_PANEL_/SPARKY_/' /opt/sparky-manager/data/panel.env
        fi
        chown -R sparky-manager:sparky-manager /opt/sparky-manager/data
        chmod 0750 /opt/sparky-manager/data
        info "Migrated panel data (database, keys, settings) from /opt/vpn-panel."
    fi
    if [ -d /opt/vpn-panel/certs ]; then
        cp -a /opt/vpn-panel/certs/. /opt/sparky-manager/certs/ 2>/dev/null || true
        chown -R root:sparky-manager /opt/sparky-manager/certs
        chmod 0750 /opt/sparky-manager/certs
    fi
    if [ -f /opt/vpn-panel/versions.env ]; then
        sed 's/^VPN_PANEL_VERSION=/SPARKY_VERSION=/' /opt/vpn-panel/versions.env > /opt/sparky-manager/versions.env
        chmod 0644 /opt/sparky-manager/versions.env
    fi
    # The Let's Encrypt renewal hook still points at the old service
    # and paths; point it at the new ones (obtain_le_ip_cert below
    # re-installs the hook as well when the certificate is handled).
    if [ -d "$HOME/.acme.sh" ]; then
        for _conf in "$HOME"/.acme.sh/*/*.conf; do
            [ -f "$_conf" ] || continue
            sed -i -e 's|/opt/vpn-panel|/opt/sparky-manager|g' \
                   -e 's|root:vpn-panel|root:sparky-manager|g' \
                   -e 's|restart vpn-panel|restart sparky-manager|g' "$_conf" || true
        done
    fi
    rm -f /etc/systemd/system/vpn-panel.service /usr/local/bin/vpn-panel
    systemctl daemon-reload 2>/dev/null || true
    info "Migration done; the old vpn-panel service is stopped and removed."
fi

# Panel port: randomised on a fresh install (like other panels), re-used
# from panel.env on a re-install, --port always wins. The chosen port is
# printed in the prompt below, in the summary and in the login box.
if [ "$PORT_GIVEN" -eq 0 ]; then
    if [ -f /opt/sparky-manager/data/panel.env ]; then
        _saved_port="$(grep -E '^SPARKY_PORT=' /opt/sparky-manager/data/panel.env | tail -n 1 | cut -d= -f2 | tr -d "'" || true)"
        if [ -n "$_saved_port" ]; then
            PANEL_PORT="$_saved_port"
        fi
    fi
    if [ -z "$PANEL_PORT" ]; then
        PANEL_PORT="$(pick_random_port)"
        info "Fresh install: random panel port ${PANEL_PORT} (override with --port, or type another at the prompt)."
    else
        info "Reusing existing panel port ${PANEL_PORT} from a previous install."
    fi
fi

# Web path: random on a fresh install (like 3X-UI's webBasePath),
# re-used from panel.env on a re-install, --web-path always wins.
if [ "$WEB_PATH_GIVEN" -eq 0 ]; then
    if [ -f /opt/sparky-manager/data/panel.env ]; then
        _saved_path="$(grep -E '^SPARKY_WEB_PATH=' /opt/sparky-manager/data/panel.env | tail -n 1 | cut -d= -f2 | tr -d "'" || true)"
        if [ -n "$_saved_path" ]; then
            WEB_PATH="$_saved_path"
        fi
    fi
    if [ -z "$WEB_PATH" ]; then
        WEB_PATH="$(pick_random_web_path)"
        info "Fresh install: random panel web path /${WEB_PATH} (override with --web-path, or type another at the prompt)."
    else
        info "Reusing existing panel web path /${WEB_PATH} from a previous install."
    fi
fi

# ---------------------------------------------------------------------------
# Interactive prompts (all skippable with --yes / flags)
# ---------------------------------------------------------------------------
ask PANEL_PORT "Panel port" "$PANEL_PORT"
ask WEB_PATH "Web path" "$WEB_PATH"

# The web path is part of the URL: strip any slashes/spaces the user
# typed and reject anything outside [A-Za-z0-9_-].
WEB_PATH="$(printf '%s' "$WEB_PATH" | tr -d ' /')"
case "$WEB_PATH" in
    *[!A-Za-z0-9_-]*) die "Invalid web path: $WEB_PATH (use letters, digits, '-' or '_')" ;;
esac
ask DOMAIN "Domain (empty = no domain, bare IP)" "$DOMAIN"
ask REALITY_SNI "Reality SNI" "$REALITY_SNI"
ask_secret ADMIN_PASSWORD "Admin password"

case "$PANEL_PORT" in
    ''|*[!0-9]*)
        die "Panel port must be a number, got: ${PANEL_PORT}"
        ;;
esac
if [ "$PANEL_PORT" -lt 1 ] || [ "$PANEL_PORT" -gt 65535 ]; then
    die "Panel port out of range (1-65535): ${PANEL_PORT}"
fi
if [ -n "$DOMAIN" ]; then
    case "$DOMAIN" in
        *[!A-Za-z0-9.-]*)
            die "Domain contains invalid characters: ${DOMAIN}"
            ;;
    esac
fi
case "$REALITY_SNI" in
    ''|*[!A-Za-z0-9.-]*)
        die "Reality SNI is empty or contains invalid characters: ${REALITY_SNI}"
        ;;
esac

# Server IP: prefer the PUBLIC address — that is what the login box,
# the self-signed certificate and the subscription links use, and a
# private/VPC address (e.g. EC2 172.31.x.x from `hostname -I`) is
# unreachable from outside. Cloud metadata first, then an external
# IP service, then the local address. Each source must return a
# dotted-quad IPv4 address or it is ignored.
SERVER_IP=""
for _ip_src in "http://169.254.169.254/latest/meta-data/public-ipv4" \
               "https://checkip.amazonaws.com" "https://ifconfig.me"; do
    _ip="$(curl -fsSL --max-time 5 -4 "$_ip_src" 2>/dev/null | tr -d '[:space:]' || true)"
    case "$_ip" in
        [0-9]*.[0-9]*.[0-9]*.[0-9]*) SERVER_IP="$_ip"; break ;;
    esac
done
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="127.0.0.1"
    warn "Could not detect the server IP; using 127.0.0.1 in the login box. Replace it with your real server IP."
fi

SUBSCRIPTION_HOST="${DOMAIN:-$SERVER_IP}"

info "Install summary:"
info "  Panel port:    ${PANEL_PORT}"
info "  Web path:    /${WEB_PATH}"
info "  Domain:        ${DOMAIN:-<none — bare IP, self-signed panel certificate>}"
info "  Server IP:     ${SERVER_IP}"
info "  Reality SNI:   ${REALITY_SNI}"
info "  Admin user:    admin"
info "  Admin pass:    ${ADMIN_PASSWORD:+<supplied>}"
if [ -z "$ADMIN_PASSWORD" ]; then
    info "  Admin pass:    <will be generated and printed in the login box>"
fi
info "  Default VPN:   VLESS+Reality TCP 443, Hysteria2 UDP 443, WireGuard UDP 51820"
info "  More in panel: OpenVPN, OpenConnect, AmneziaWG, IKEv2 (create as inbounds)"

# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------
info "Updating apt and installing packages ..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates git unzip \
    python3 python3-venv python3-pip \
    wireguard wireguard-tools nftables iproute2 openssl cron socat \
    openvpn ocserv \
    strongswan strongswan-swanctl strongswan-pki \
    libcharon-extra-plugins libcharon-extauth-plugins

# ---------------------------------------------------------------------------
# AmneziaWG — best-effort, never breaks the install.
# There is no Ubuntu package: Amnezia's Launchpad PPA. The PPA publishes
# no suite for Ubuntu 26.04 (resolute), so the suite is pinned to noble
# there. DKMS needs the matching kernel headers. Any failure here only
# warns — the panel marks AmneziaWG inbounds as unavailable and the
# rest of the install continues.
# ---------------------------------------------------------------------------
install_amneziawg() {
    if command -v awg-quick >/dev/null 2>&1; then
        info "AmneziaWG tools already installed."
        return 0
    fi
    info "Installing AmneziaWG (best-effort; a failure only disables AmneziaWG) ..."
    local codename
    codename="$(. /etc/os-release 2>/dev/null && echo "${VERSION_CODENAME:-noble}")"
    (
        apt-get install -y -qq software-properties-common
        add-apt-repository -y ppa:amnezia/ppa
        if [ "$codename" = "resolute" ]; then
            # The PPA has no resolute suite — pin the added source to noble.
            sed -i 's/Suites: resolute/Suites: noble/' \
                /etc/apt/sources.list.d/amnezia-ubuntu-ppa-*.sources 2>/dev/null || true
        fi
        apt-get update -qq
        apt-get install -y -qq "linux-headers-$(uname -r)" amneziawg amneziawg-tools
    ) >/dev/null 2>&1 || true
    if command -v awg-quick >/dev/null 2>&1; then
        info "AmneziaWG installed."
        return 0
    fi
    warn "AmneziaWG could not be installed (the kernel module may be unavailable on this kernel). The panel will mark AmneziaWG inbounds as unavailable; everything else works."
    return 0
}
install_amneziawg

# ---------------------------------------------------------------------------
# Directories and system user
# ---------------------------------------------------------------------------
info "Creating directories and the sparky-manager system user ..."
mkdir -p /opt/sparky-manager/app /opt/sparky-manager/data /opt/sparky-manager/certs \
         /opt/sparky-manager/data/logs /opt/sparky-manager/data/ca \
         /usr/local/etc/xray /etc/sing-box /etc/wireguard \
         /etc/openvpn/server /etc/ocserv /etc/swanctl \
         /etc/amnezia/amneziawg /var/log/openvpn
if ! id sparky-manager >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /opt/sparky-manager \
            --shell /usr/sbin/nologin sparky-manager
fi
chown -R sparky-manager:sparky-manager /opt/sparky-manager
chmod 0750 /opt/sparky-manager/data /opt/sparky-manager/certs
chmod 0755 /opt/sparky-manager/app
# The panel writes the new protocols' server configs (and the ocserv
# password file) by atomic rename, so their directories must be
# group-writable like /etc/wireguard below. The VPN CA dir holds the
# CA private key: root-only for the key, group-readable for the certs.
chown root:sparky-manager /etc/openvpn/server /etc/ocserv /etc/swanctl /etc/amnezia/amneziawg
chmod 2770 /etc/openvpn/server /etc/ocserv /etc/swanctl /etc/amnezia/amneziawg
chown root:sparky-manager /opt/sparky-manager/data/logs /opt/sparky-manager/data/ca
chmod 0750 /opt/sparky-manager/data/logs /opt/sparky-manager/data/ca

# Privileges: the panel runs as the unprivileged sparky-manager user,
# but it must restart its services and read WireGuard transfer stats.
# Grant exactly that via sudo (NOPASSWD, validated with visudo), and
# make /etc/wireguard group-writable so the panel can atomically
# replace wg0.conf (write wg0.conf.tmp + rename) — the same reason
# the Xray / sing-box config directories above are group-writable.
# Without this, config rebuilds fail with "Access denied" (systemctl)
# and "Permission denied: /etc/wireguard/wg0.conf.tmp".
if command -v sudo >/dev/null 2>&1 && command -v visudo >/dev/null 2>&1; then
    cat > /etc/sudoers.d/sparky-manager <<'EOF'
# sparky-manager panel: restart its services and read WireGuard stats.
# Installed by install.sh; validated with visudo -cf before use.
# v12: the WireGuard apply path uses `systemctl start` (not restart)
# and `wg show` (interface check), swanctl loads the IKEv2 config,
# ocserv -t validates its config, and journalctl tails give the panel
# the real error behind a failed restart (see app.wgapply / app.main).
sparky-manager ALL=(root) NOPASSWD: /usr/bin/systemctl restart xray, /usr/bin/systemctl restart sing-box, /usr/bin/systemctl restart sparky-manager, /usr/bin/systemctl restart wg-quick@wg0, /usr/bin/systemctl restart openvpn-server@sparky-manager, /usr/bin/systemctl restart ocserv, /usr/bin/systemctl restart strongswan, /usr/bin/systemctl start wg-quick@wg0, /usr/bin/systemctl start awg-quick@awg0, /usr/bin/systemctl is-active xray, /usr/bin/systemctl is-active sing-box, /usr/bin/systemctl is-active sparky-manager, /usr/bin/systemctl is-active wg-quick@wg0, /usr/bin/systemctl status xray, /usr/bin/systemctl status sing-box, /usr/bin/systemctl status sparky-manager, /usr/bin/systemctl status wg-quick@wg0, /usr/bin/wg show wg0 transfer, /usr/bin/wg show wg0, /usr/bin/awg show awg0, /usr/bin/wg-quick up wg0, /usr/bin/wg-quick down wg0, /usr/bin/swanctl --load-all, /usr/bin/swanctl --list-conns, /usr/bin/ocserv -t -c *, /usr/bin/journalctl -u xray -n 50 --no-pager, /usr/bin/journalctl -u sing-box -n 50 --no-pager, /usr/bin/journalctl -u sparky-manager -n 50 --no-pager, /usr/bin/journalctl -u wg-quick@wg0 -n 50 --no-pager, /usr/bin/journalctl -u openvpn-server@sparky-manager -n 50 --no-pager, /usr/bin/journalctl -u ocserv -n 50 --no-pager, /usr/bin/journalctl -u strongswan -n 50 --no-pager, /usr/bin/journalctl -u awg-quick@awg0 -n 50 --no-pager
EOF
    chmod 0440 /etc/sudoers.d/sparky-manager
    chown root:root /etc/sudoers.d/sparky-manager
    if ! visudo -cf /etc/sudoers.d/sparky-manager >/dev/null 2>&1; then
        rm -f /etc/sudoers.d/sparky-manager
        die "sudoers file failed validation — refusing to continue with a broken sudoers setup."
    fi
else
    warn "sudo/visudo not found; the panel will not be able to restart services. Install sudo and re-run the installer."
fi
chown root:sparky-manager /etc/wireguard
chmod 2770 /etc/wireguard

# ---------------------------------------------------------------------------
# App source: use the local repo checkout when present, else clone it.
# The installer is run either from a cloned repo (./app exists) or via
# curl pipe (no local copy — clone to a temp dir). Nothing is pushed.
# ---------------------------------------------------------------------------
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
REPO_DIR=""
if [ -d ./app ] && [ -f ./requirements.txt ]; then
    REPO_DIR="$(pwd)"
    info "Using local repo checkout: ${REPO_DIR}"
else
    info "No local checkout found; cloning ${REPO_URL} ..."
    git clone --depth 1 "$REPO_URL" "${WORK_DIR}/repo" || \
        die "Could not clone ${REPO_URL}. If the repo does not exist yet, run the installer from a cloned copy instead (git clone, then sudo bash install.sh)."
    REPO_DIR="${WORK_DIR}/repo"
fi
[ -d "${REPO_DIR}/app" ] || die "Repo checkout has no app/ directory: ${REPO_DIR}"

if [ -f "${REPO_DIR}/app/__init__.py" ]; then
    PANEL_VERSION="$(grep -E '^__version__' "${REPO_DIR}/app/__init__.py" | cut -d'"' -f2 || true)"
    PANEL_VERSION="${PANEL_VERSION:-1.2.0}"
fi

info "Copying the panel app to /opt/sparky-manager ..."
cp -a "${REPO_DIR}/app/." /opt/sparky-manager/app/
cp -a "${REPO_DIR}/requirements.txt" /opt/sparky-manager/requirements.txt
if [ -d "${REPO_DIR}/scripts" ]; then
    mkdir -p /opt/sparky-manager/scripts
    cp -a "${REPO_DIR}/scripts/." /opt/sparky-manager/scripts/
fi
if [ -d "${REPO_DIR}/systemd" ]; then
    mkdir -p /opt/sparky-manager/systemd
    cp -a "${REPO_DIR}/systemd/." /opt/sparky-manager/systemd/
fi
chown -R sparky-manager:sparky-manager /opt/sparky-manager/app /opt/sparky-manager/data

# ---------------------------------------------------------------------------
# Python virtualenv
# ---------------------------------------------------------------------------
info "Creating the Python virtualenv and installing dependencies ..."
if [ ! -x /opt/sparky-manager/venv/bin/python ]; then
    python3 -m venv /opt/sparky-manager/venv
fi
/opt/sparky-manager/venv/bin/pip install --disable-pip-version-check --quiet \
    --upgrade pip
/opt/sparky-manager/venv/bin/pip install --disable-pip-version-check \
    -r /opt/sparky-manager/requirements.txt

# ---------------------------------------------------------------------------
# Core binaries: latest stable Xray-core + sing-box from GitHub releases.
# The sing-box repo is SagerNet/sing-box (verified). SHA256 is checked
# from the release API's per-asset digest when GitHub provides one.
# ---------------------------------------------------------------------------
# github_asset REPO REGEX JSONFILE — print "tag<TAB>download-url<TAB>digest"
# for the first asset whose name matches REGEX.
github_asset() {
    python3 - "$1" "$2" "$3" <<'PY'
import json, re, sys
repo, pattern, path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
tag = data.get("tag_name", "")
rx = re.compile(pattern)
for asset in data.get("assets", []):
    name = asset.get("name", "")
    if rx.search(name):
        print(f"{tag}\t{asset.get('browser_download_url', '')}\t{asset.get('digest', '')}")
        sys.exit(0)
print(f"no asset matching {pattern} in {repo} {tag}", file=sys.stderr)
sys.exit(1)
PY
}

# download_core REPO REGEX DESTFILE LABEL — fetch latest release metadata,
# download the matching asset, verify its SHA256 when the API provides one.
# Prints the release tag on stdout.
download_core() {
    local repo="$1" pattern="$2" dest="$3" label="$4"
    local json_file tag url digest expected actual
    json_file="${WORK_DIR}/${label}.json"
    info "Checking latest ${label} release (${repo}) ..."
    curl -fsSL -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${repo}/releases/latest" \
        -o "$json_file" || die "Could not reach the GitHub API for ${repo}. Check network access to api.github.com."
    local asset_info
    asset_info="$(github_asset "$repo" "$pattern" "$json_file")" || \
        die "No ${label} asset matching ${pattern} in the latest ${repo} release."
    IFS="$(printf '\t')" read -r tag url digest <<EOF
$asset_info
EOF
    [ -n "$tag" ] && [ -n "$url" ] || die "Could not parse the ${label} release info."
    info "Downloading ${label} ${tag} ..."
    curl -fsSL "$url" -o "$dest" || die "Download failed: ${url}"
    if [ -n "$digest" ]; then
        case "$digest" in
            sha256:*)
                expected="${digest#sha256:}"
                actual="$(sha256sum "$dest" | awk '{print $1}')"
                [ "$expected" = "$actual" ] || \
                    die "SHA256 mismatch for ${label} ${tag}: expected ${expected}, got ${actual}"
                info "${label} SHA256 verified."
                ;;
            *)
                warn "Unknown digest format for ${label}; skipping verification."
                ;;
        esac
    else
        warn "No SHA256 digest published for ${label} ${tag}; skipping verification."
    fi
    printf '%s' "$tag"
}

info "Downloading latest stable cores ..."
XRAY_TAG="$(download_core "XTLS/Xray-core" "$XRAY_ASSET_RE" "${WORK_DIR}/xray.zip" "xray")"
SINGBOX_TAG="$(download_core "SagerNet/sing-box" "$SINGBOX_ASSET_RE" "${WORK_DIR}/sing-box.tar.gz" "sing-box")"
info "Xray-core ${XRAY_TAG} / sing-box ${SINGBOX_TAG}"

info "Installing core binaries to /usr/local/bin ..."
mkdir -p "${WORK_DIR}/xray-unzip" "${WORK_DIR}/singbox-untar"
unzip -o -q "${WORK_DIR}/xray.zip" -d "${WORK_DIR}/xray-unzip"
[ -x "${WORK_DIR}/xray-unzip/xray" ] || die "Xray archive did not contain an xray binary."
install -m 0755 "${WORK_DIR}/xray-unzip/xray" /usr/local/bin/xray
# Geo data: Xray looks for geoip.dat / geosite.dat NEXT TO its binary
# (/usr/local/bin) — the config dir is not searched. The rendered and
# minimal configs both use a geoip:private routing rule, so without
# these files `xray run -test` fails at install time. Install them
# beside the binary (and keep a copy in the config dir). If a future
# Xray archive drops them, fetch them from the official geo repos.
for dat in geoip.dat geosite.dat; do
    if [ -f "${WORK_DIR}/xray-unzip/${dat}" ]; then
        install -m 0644 "${WORK_DIR}/xray-unzip/${dat}" "/usr/local/bin/${dat}"
        install -m 0644 "${WORK_DIR}/xray-unzip/${dat}" "/usr/local/etc/xray/${dat}"
    else
        warn "Xray archive has no ${dat}; downloading it from the official geo repo ..."
        case "$dat" in
            geoip.dat)   _geo_url="https://github.com/v2fly/geoip/releases/latest/download/geoip.dat" ;;
            geosite.dat) _geo_url="https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat" ;;
        esac
        curl -fsSL "$_geo_url" -o "/usr/local/bin/${dat}" && \
            install -m 0644 "/usr/local/bin/${dat}" "/usr/local/etc/xray/${dat}" || \
            die "Could not obtain ${dat} (needed for the geoip:private routing rule)."
    fi
done
tar -xzf "${WORK_DIR}/sing-box.tar.gz" -C "${WORK_DIR}/singbox-untar"
SINGBOX_BIN="$(find "${WORK_DIR}/singbox-untar" -type f -name sing-box | head -n 1)"
[ -n "$SINGBOX_BIN" ] || die "sing-box archive did not contain a sing-box binary."
install -m 0755 "$SINGBOX_BIN" /usr/local/bin/sing-box

{
    printf 'XRAY_VERSION=%s\n' "$XRAY_TAG"
    printf 'SINGBOX_VERSION=%s\n' "$SINGBOX_TAG"
    printf 'SPARKY_VERSION=%s\n' "$PANEL_VERSION"
    printf 'INSTALLED_AT=%s\n' "$(date -u +%FT%TZ)"
} > /opt/sparky-manager/versions.env
chmod 0644 /opt/sparky-manager/versions.env
info "Installed versions recorded in /opt/sparky-manager/versions.env"

# ---------------------------------------------------------------------------
# Secrets — reuse existing ones on re-install (idempotent), else generate.
# Stored in /opt/sparky-manager/data/install.env (0640, root:sparky-manager) so the
# panel service user can read it on first run; no other user can.
# Never printed to the terminal except the admin password in the login box.
# ---------------------------------------------------------------------------
INSTALL_ENV="/opt/sparky-manager/data/install.env"
if [ -f "$INSTALL_ENV" ]; then
    # shellcheck source=/dev/null
    . "$INSTALL_ENV"
    info "Reusing existing keys and admin password from a previous install."
fi

if [ -z "${REALITY_PRIVATE_KEY:-}" ] || [ -z "${REALITY_PUBLIC_KEY:-}" ]; then
    info "Generating a Reality X25519 keypair (xray x25519) ..."
    X25519_OUT="$(/usr/local/bin/xray x25519)"
    REALITY_PRIVATE_KEY="$(printf '%s' "$X25519_OUT" | grep -i 'private' | awk -F': ' '{print $2}' | tr -d '[:space:]')"
    REALITY_PUBLIC_KEY="$(printf '%s' "$X25519_OUT" | grep -i 'public' | awk -F': ' '{print $2}' | tr -d '[:space:]')"
    [ -n "$REALITY_PRIVATE_KEY" ] && [ -n "$REALITY_PUBLIC_KEY" ] || \
        die "Failed to generate a Reality keypair with 'xray x25519'."
fi
if [ -z "${REALITY_SHORT_ID:-}" ]; then
    REALITY_SHORT_ID="$(openssl rand -hex 4)"
fi
if [ -z "${WG_PRIVATE_KEY:-}" ]; then
    info "Generating the WireGuard server keypair ..."
    if command -v wg >/dev/null 2>&1; then
        WG_PRIVATE_KEY="$(wg genkey)"
        WG_PUBLIC_KEY="$(printf '%s' "$WG_PRIVATE_KEY" | wg pubkey)"
    else
        warn "'wg' not found; generating a WireGuard key with openssl. Derive the public key later with: echo <private-key> | wg pubkey"
        WG_PRIVATE_KEY="$(openssl rand -base64 32 | tr -d '\n')"
        WG_PUBLIC_KEY=""
    fi
fi
# AmneziaWG uses the same X25519 key format as WireGuard (a separate
# keypair — wg0 and awg0 are different interfaces and must never
# share a server key).
if [ -z "${AWG_PRIVATE_KEY:-}" ]; then
    info "Generating the AmneziaWG server keypair ..."
    if command -v wg >/dev/null 2>&1; then
        AWG_PRIVATE_KEY="$(wg genkey)"
        AWG_PUBLIC_KEY="$(printf '%s' "$AWG_PRIVATE_KEY" | wg pubkey)"
    else
        warn "'wg' not found; generating an AmneziaWG key with openssl. Derive the public key later with: echo <private-key> | wg pubkey"
        AWG_PRIVATE_KEY="$(openssl rand -base64 32 | tr -d '\n')"
        AWG_PUBLIC_KEY=""
    fi
fi
# A valid 2022-blake3-aes-128-gcm key is base64 of exactly 16 bytes.
# Older installs stored a 24-byte token, which Xray rejects ("bad
# key") — and re-installs reuse it from install.env, so validate the
# stored value and regenerate when it is not a valid 16-byte key.
_ss_key_bytes() {
    printf '%s' "$1" | base64 -d 2>/dev/null | wc -c | tr -d ' '
}
if [ -z "${SS_PASSWORD:-}" ] || [ "$(_ss_key_bytes "$SS_PASSWORD")" != "16" ]; then
    [ -n "${SS_PASSWORD:-}" ] && warn "Stored Shadowsocks key is not a valid 16-byte 2022-blake3 key; generating a new one."
    SS_PASSWORD="$(openssl rand -base64 16 | tr -d '\n')"
fi
if [ -z "${HY2_PASSWORD:-}" ]; then
    HY2_PASSWORD="$(openssl rand -base64 24 | tr -d '\n')"
fi
if [ -z "$ADMIN_PASSWORD" ]; then
    if [ -n "${ADMIN_PASSWORD_STORED:-}" ]; then
        ADMIN_PASSWORD="$ADMIN_PASSWORD_STORED"
    else
        ADMIN_PASSWORD="$(openssl rand -hex 16)"
        info "Generated a new admin password (printed in the login box at the end)."
    fi
fi

umask 077
{
    printf 'ADMIN_PASSWORD_STORED=%s\n' "$(sq "$ADMIN_PASSWORD")"
    printf 'REALITY_PRIVATE_KEY=%s\n' "$(sq "$REALITY_PRIVATE_KEY")"
    printf 'REALITY_PUBLIC_KEY=%s\n' "$(sq "$REALITY_PUBLIC_KEY")"
    printf 'REALITY_SHORT_ID=%s\n' "$(sq "$REALITY_SHORT_ID")"
    printf 'REALITY_SNI=%s\n' "$(sq "$REALITY_SNI")"
    printf 'WG_PRIVATE_KEY=%s\n' "$(sq "$WG_PRIVATE_KEY")"
    printf 'WG_PUBLIC_KEY=%s\n' "$(sq "$WG_PUBLIC_KEY")"
    printf 'AWG_PRIVATE_KEY=%s\n' "$(sq "$AWG_PRIVATE_KEY")"
    printf 'AWG_PUBLIC_KEY=%s\n' "$(sq "$AWG_PUBLIC_KEY")"
    printf 'SS_PASSWORD=%s\n' "$(sq "$SS_PASSWORD")"
    printf 'HY2_PASSWORD=%s\n' "$(sq "$HY2_PASSWORD")"
} > "$INSTALL_ENV"
chmod 0640 "$INSTALL_ENV"
chown root:sparky-manager "$INSTALL_ENV"

# Panel runtime settings for the app (read by app/config.py via env vars).
# The secret values below are ALSO in install.env; they are repeated here
# as SPARKY_* variables so the app can seed its database from them on
# first run (admin password, Reality keypair, WireGuard keys) instead of
# generating different ones. The app must read these on first run — see
# the bootstrap note in the install report if it does not yet.
{
    printf 'SPARKY_HOME=%s\n' "$(sq "/opt/sparky-manager")"
    printf 'SPARKY_PORT=%s\n' "$(sq "$PANEL_PORT")"
    printf 'SPARKY_WEB_PATH=%s\n' "$(sq "$WEB_PATH")"
    printf 'SPARKY_HOST=%s\n' "$(sq "0.0.0.0")"
    printf 'SPARKY_DOMAIN=%s\n' "$(sq "$DOMAIN")"
    printf 'SPARKY_SUBSCRIPTION_HOST=%s\n' "$(sq "$SUBSCRIPTION_HOST")"
    printf 'SPARKY_REALITY_SNI=%s\n' "$(sq "$REALITY_SNI")"
    printf 'SPARKY_ADMIN_PASSWORD=%s\n' "$(sq "$ADMIN_PASSWORD")"
    printf 'SPARKY_REALITY_PRIVATE_KEY=%s\n' "$(sq "$REALITY_PRIVATE_KEY")"
    printf 'SPARKY_REALITY_PUBLIC_KEY=%s\n' "$(sq "$REALITY_PUBLIC_KEY")"
    printf 'SPARKY_REALITY_SHORT_ID=%s\n' "$(sq "$REALITY_SHORT_ID")"
    printf 'SPARKY_WG_PRIVATE_KEY=%s\n' "$(sq "$WG_PRIVATE_KEY")"
    printf 'SPARKY_WG_PUBLIC_KEY=%s\n' "$(sq "$WG_PUBLIC_KEY")"
    printf 'SPARKY_AWG_PRIVATE_KEY=%s\n' "$(sq "$AWG_PRIVATE_KEY")"
    printf 'SPARKY_AWG_PUBLIC_KEY=%s\n' "$(sq "$AWG_PUBLIC_KEY")"
} > /opt/sparky-manager/data/panel.env
chmod 0640 /opt/sparky-manager/data/panel.env
chown root:sparky-manager /opt/sparky-manager/data/panel.env

# obtain_le_ip_cert — replace the self-signed panel certificate with a
# TRUSTED Let's Encrypt certificate for the bare public IP, the same
# trick 3x-ui's SSL menu uses (no domain needed). Since 2026-01-15
# Let's Encrypt issues free certificates for public IP addresses, but
# only under the `shortlived` profile: valid ~160 hours (~6 days).
# acme.sh's cron renews it automatically and the --reloadcmd below
# re-installs it and restarts the panel (and sing-box, whose Hysteria2
# inbound serves the same certificate). Needs TCP 80 reachable from
# the internet for the HTTP-01 challenge. Returns 0 on success, 1
# otherwise — the caller keeps the self-signed certificate and the
# install continues; re-running the installer retries it.
obtain_le_ip_cert() {
    [ -z "$DOMAIN" ] || return 1
    case "$SERVER_IP" in
        10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*|127.*|169.254.*|0.*)
            return 1 ;;
    esac
    if (exec 3<>/dev/tcp/127.0.0.1/80) 2>/dev/null; then
        warn "Port 80 is already in use; skipping the trusted IP certificate (keeping the self-signed one)."
        return 1
    fi
    # Default first (ask only overwrites it when the user types a reply;
    # with no usable terminal the variable would otherwise stay unset
    # and `set -u` would kill the script when it is read below).
    LE_IP_CERT="Y"
    ask LE_IP_CERT "Trusted Let's Encrypt certificate for ${SERVER_IP} (no browser warning)" "Y"
    case "$LE_IP_CERT" in
        Y|y|yes|YES|"") ;;
        *) info "Skipping the trusted IP certificate (keeping the self-signed one)."; return 1 ;;
    esac
    local acme="$HOME/.acme.sh/acme.sh"
    if [ ! -x "$acme" ]; then
        info "Installing acme.sh (Let's Encrypt client) ..."
        if ! curl -fsSL https://get.acme.sh | sh >/dev/null 2>&1; then
            warn "Could not install acme.sh; keeping the self-signed certificate."
            return 1
        fi
    fi
    # acme.sh defaults to ZeroSSL (needs an email); force Let's Encrypt.
    "$acme" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
    # A certificate already issued for this IP (e.g. by another panel
    # earlier) is NOT a failure: --issue then prints "Skipping" and
    # may exit nonzero, but the certificate is there and usable — so
    # install it instead of keeping the self-signed one. An ECC
    # certificate lives in <IP>_ecc/ instead of <IP>/.
    local _cert_file _ecc_args
    _resolve_le_cert() {
        _cert_file="$HOME/.acme.sh/$SERVER_IP/fullchain.cer"
        _ecc_args=()
        if [ ! -s "$_cert_file" ] && [ -s "$HOME/.acme.sh/${SERVER_IP}_ecc/fullchain.cer" ]; then
            _cert_file="$HOME/.acme.sh/${SERVER_IP}_ecc/fullchain.cer"
            _ecc_args=(--ecc)
        fi
    }
    _le_cert_usable() {
        [ -s "$_cert_file" ] && openssl x509 -noout -checkend 0 -in "$_cert_file" 2>/dev/null
    }
    _resolve_le_cert
    if ! _le_cert_usable; then
        info "Requesting a Let's Encrypt certificate for ${SERVER_IP} (HTTP-01 on port 80) ..."
        local _acme_log
        _acme_log="$(mktemp)"
        if ! "$acme" --issue -d "$SERVER_IP" --standalone --server letsencrypt \
                --certificate-profile shortlived --days 6 --httpport 80 >"$_acme_log" 2>&1; then
            _resolve_le_cert
            if ! _le_cert_usable; then
                warn "Could not obtain the Let's Encrypt IP certificate. Is TCP 80 open in the firewall/security group? Last lines from acme.sh:"
                tail -n 5 "$_acme_log" || true
                warn "Keeping the self-signed certificate — open TCP 80 and re-run the installer to retry."
                rm -f "$_acme_log"
                return 1
            fi
            info "Let's Encrypt certificate for ${SERVER_IP} already issued; installing it ..."
        fi
        rm -f "$_acme_log"
    else
        info "Let's Encrypt certificate for ${SERVER_IP} already issued; installing it ..."
    fi
    # Back up the self-signed pair before overwriting it, so a bad
    # install can be rolled back instead of breaking the panel's TLS.
    cp /opt/sparky-manager/certs/fullchain.pem /opt/sparky-manager/certs/fullchain.pem.bak 2>/dev/null || true
    cp /opt/sparky-manager/certs/privkey.pem /opt/sparky-manager/certs/privkey.pem.bak 2>/dev/null || true
    info "Installing the trusted certificate for the panel ..."
    local _reload="chmod 0640 /opt/sparky-manager/certs/privkey.pem; chown root:sparky-manager /opt/sparky-manager/certs/privkey.pem /opt/sparky-manager/certs/fullchain.pem; systemctl restart sparky-manager sing-box"
    if ! "$acme" --installcert -d "$SERVER_IP" "${_ecc_args[@]}" \
            --key-file /opt/sparky-manager/certs/privkey.pem \
            --fullchain-file /opt/sparky-manager/certs/fullchain.pem \
            --reloadcmd "$_reload" >/dev/null 2>&1; then
        warn "Could not install the Let's Encrypt certificate; keeping the self-signed one."
        mv /opt/sparky-manager/certs/fullchain.pem.bak /opt/sparky-manager/certs/fullchain.pem 2>/dev/null || true
        mv /opt/sparky-manager/certs/privkey.pem.bak /opt/sparky-manager/certs/privkey.pem 2>/dev/null || true
        return 1
    fi
    chmod 0640 /opt/sparky-manager/certs/privkey.pem
    chmod 0644 /opt/sparky-manager/certs/fullchain.pem
    chown root:sparky-manager /opt/sparky-manager/certs/privkey.pem /opt/sparky-manager/certs/fullchain.pem
    if ! openssl x509 -noout -issuer -in /opt/sparky-manager/certs/fullchain.pem 2>/dev/null | grep -qi "Let's Encrypt"; then
        warn "Installed certificate is not from Let's Encrypt; restoring the self-signed one."
        mv /opt/sparky-manager/certs/fullchain.pem.bak /opt/sparky-manager/certs/fullchain.pem 2>/dev/null || true
        mv /opt/sparky-manager/certs/privkey.pem.bak /opt/sparky-manager/certs/privkey.pem 2>/dev/null || true
        return 1
    fi
    rm -f /opt/sparky-manager/certs/fullchain.pem.bak /opt/sparky-manager/certs/privkey.pem.bak
    # Make sure acme.sh's renewal cron job exists (another panel may
    # have installed acme.sh without it).
    "$acme" --install-cronjob >/dev/null 2>&1 || true
    CERT_REGENERATED=1
    LE_CERT_OK=1
    info "Trusted Let's Encrypt certificate installed for ${SERVER_IP} (valid ~6 days, auto-renewed by acme.sh)."
    return 0
}

# ---------------------------------------------------------------------------
# Panel certificate — self-signed when no domain is given (DESIGN §7).
# The browser WILL warn about it; the fingerprint is printed in the
# login box so it can be checked. With a domain, this self-signed cert
# is only an interim: a real Let's Encrypt certificate is an option in
# the panel settings afterwards, never a requirement at install time.
# ---------------------------------------------------------------------------
CERT_CN="${DOMAIN:-$SERVER_IP}"
# Regenerate the self-signed cert when it was made for a different
# bare IP (e.g. an earlier install used the private/VPC address
# before public-IP detection existed) — otherwise the browser shows
# a name mismatch on top of the self-signed warning. With a domain
# the cert is keyed to the domain and is left alone.
_cert_cn() {
    openssl x509 -noout -subject -nameopt RFC2253 \
        -in /opt/sparky-manager/certs/fullchain.pem 2>/dev/null | \
        sed -n 's/^subject=CN=//p' | cut -d, -f1
}
CERT_REGENERATED=0
if [ ! -f /opt/sparky-manager/certs/fullchain.pem ] || [ ! -f /opt/sparky-manager/certs/privkey.pem ] \
   || { [ -z "$DOMAIN" ] && [ "$(_cert_cn)" != "$SERVER_IP" ]; }; then
    info "Generating a self-signed panel certificate (365 days, CN=${CERT_CN}) ..."
    CERT_REGENERATED=1
    if [ -n "$DOMAIN" ]; then
        SAN="DNS:${DOMAIN},IP:${SERVER_IP}"
    else
        SAN="IP:${SERVER_IP}"
    fi
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /opt/sparky-manager/certs/privkey.pem \
        -out /opt/sparky-manager/certs/fullchain.pem \
        -days 365 -subj "/CN=${CERT_CN}" \
        -addext "subjectAltName=${SAN}" 2>/dev/null
    # 0640, not 0600: the panel runs as user sparky-manager (see the
    # systemd unit), so the key must be group-readable or uvicorn
    # dies with PermissionError in load_cert_chain. Still private:
    # only root and the sparky-manager group can read it.
    chmod 0640 /opt/sparky-manager/certs/privkey.pem
    chmod 0644 /opt/sparky-manager/certs/fullchain.pem
    chown root:sparky-manager /opt/sparky-manager/certs/privkey.pem /opt/sparky-manager/certs/fullchain.pem
else
    info "Keeping the existing panel certificate."
fi
# Try for a trusted certificate (no domain needed); falls back to the
# self-signed one above on any failure.
LE_CERT_OK=0
obtain_le_ip_cert || true
CERT_FINGERPRINT="$(openssl x509 -noout -fingerprint -sha256 \
    -in /opt/sparky-manager/certs/fullchain.pem | cut -d'=' -f2)"
CERT_ISSUER="$(openssl x509 -noout -issuer -in /opt/sparky-manager/certs/fullchain.pem 2>/dev/null | sed 's/^issuer=//')"
CERT_EXPIRY="$(openssl x509 -noout -enddate -in /opt/sparky-manager/certs/fullchain.pem 2>/dev/null | cut -d= -f2)"

# ---------------------------------------------------------------------------
# VPN server CA — one trust anchor for OpenVPN, ocserv and IKEv2.
# NOT the panel's own certificate (that one rotates with Let's Encrypt):
# a dedicated CA + server cert, RSA, 825 days (the iOS limit for a
# server cert), SAN = IP:<public-ip> and/or DNS:<domain>. Generated
# once and reused on re-install; the panel reads the CA cert to embed
# it in client files (.ovpn / .mobileconfig) and the server configs
# reference these paths directly (no copies to drift, except the
# swanctl copies below, which charon reads at load time).
# ---------------------------------------------------------------------------
generate_vpn_ca() {
    local ca_dir="/opt/sparky-manager/data/ca"
    mkdir -p "$ca_dir"
    if [ -f "$ca_dir/ca-cert.pem" ] && [ -f "$ca_dir/server-cert.pem" ] \
       && [ -f "$ca_dir/ca-key.pem" ] && [ -f "$ca_dir/server-key.pem" ]; then
        info "VPN server CA already exists; reusing it."
    else
        info "Generating the VPN server CA + server certificate (825 days) ..."
        local san
        if [ -n "$DOMAIN" ]; then
            san="IP:${SERVER_IP},DNS:${DOMAIN}"
        else
            san="IP:${SERVER_IP}"
        fi
        openssl req -x509 -newkey rsa:4096 -nodes \
            -keyout "$ca_dir/ca-key.pem" -out "$ca_dir/ca-cert.pem" \
            -days 825 -subj "/CN=sparky-manager CA" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null || \
            die "Failed to generate the VPN CA certificate."
        openssl req -newkey rsa:3072 -nodes \
            -keyout "$ca_dir/server-key.pem" -out "$ca_dir/server.csr" \
            -subj "/CN=${CERT_CN}" 2>/dev/null || \
            die "Failed to generate the VPN server key."
        # `openssl x509 -req` does not accept -addext on OpenSSL 3.0
        # (Ubuntu 22.04/24.04), so the extensions go through a temp
        # extfile instead.
        local _extfile
        _extfile="$(mktemp)"
        printf '[v3_req]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nsubjectAltName=%s\nextendedKeyUsage=serverAuth\n' \
            "$san" > "$_extfile"
        openssl x509 -req -in "$ca_dir/server.csr" \
            -CA "$ca_dir/ca-cert.pem" -CAkey "$ca_dir/ca-key.pem" \
            -CAcreateserial -out "$ca_dir/server-cert.pem" -days 825 \
            -extensions v3_req -extfile "$_extfile" 2>/dev/null || \
            die "Failed to sign the VPN server certificate."
        rm -f "$_extfile" "$ca_dir/server.csr" "$ca_dir/ca-cert.srl"
    fi
    chmod 0644 "$ca_dir/ca-cert.pem" "$ca_dir/server-cert.pem"
    chmod 0600 "$ca_dir/ca-key.pem" "$ca_dir/server-key.pem"
    chown root:root "$ca_dir/ca-key.pem" "$ca_dir/server-key.pem"
    chown root:sparky-manager "$ca_dir/ca-cert.pem" "$ca_dir/server-cert.pem"
    chmod 0750 "$ca_dir"
    chown root:sparky-manager "$ca_dir"
    # strongSwan reads the CA / server cert from its own directories.
    mkdir -p /etc/swanctl/x509ca /etc/swanctl/x509 /etc/swanctl/private
    cp "$ca_dir/ca-cert.pem" /etc/swanctl/x509ca/ca-cert.pem
    cp "$ca_dir/server-cert.pem" /etc/swanctl/x509/server-cert.pem
    cp "$ca_dir/server-key.pem" /etc/swanctl/private/server-key.pem
    chmod 0644 /etc/swanctl/x509ca/ca-cert.pem /etc/swanctl/x509/server-cert.pem
    chmod 0600 /etc/swanctl/private/server-key.pem
}
generate_vpn_ca

# ---------------------------------------------------------------------------
# Default configs: run the panel's render script when it exists, else
# write minimal working configs (VLESS+Reality + Shadowsocks in Xray,
# Hysteria2 in sing-box, WireGuard wg0). The panel re-renders these from
# its database whenever users or inbounds change.
# ---------------------------------------------------------------------------
# Rendered configs only carry VPN inbounds when the DB has usable
# clients; on a fresh install there are none yet, so the rendered
# Xray config would contain only the api inbound. In that case keep
# the minimal defaults (listening inbounds, empty client lists) — the
# panel re-renders from the DB as soon as the first user is created.
_rendered_has_vpn_inbounds() {
    /opt/sparky-manager/venv/bin/python -c '
import json, sys
try:
    cfg = json.load(open("/opt/sparky-manager/data/rendered/xray.json"))
except Exception:
    sys.exit(1)
tags = [i.get("tag") for i in cfg.get("inbounds", []) if isinstance(i, dict)]
sys.exit(0 if any(t and t != "api" for t in tags) else 1)
'
}

RENDERED=0
if [ -f /opt/sparky-manager/scripts/render_configs.py ]; then
    info "Rendering configs with the panel's render script ..."
    if SPARKY_HOME=/opt/sparky-manager /opt/sparky-manager/venv/bin/python \
            /opt/sparky-manager/scripts/render_configs.py; then
        if _rendered_has_vpn_inbounds; then
            # The render script writes to data/rendered/ — copy the
            # outputs to the live config paths the cores actually read.
            cp /opt/sparky-manager/data/rendered/xray.json "$XRAY_CONFIG"
            cp /opt/sparky-manager/data/rendered/sing-box.json "$SINGBOX_CONFIG"
            if [ -f /opt/sparky-manager/data/rendered/wg0.conf ]; then
                cp /opt/sparky-manager/data/rendered/wg0.conf "$WG_CONFIG"
                chmod 0660 "$WG_CONFIG"
                chown root:sparky-manager "$WG_CONFIG"
            fi
            RENDERED=1
        else
            info "Rendered configs have no VPN inbounds yet (no users); keeping minimal defaults."
        fi
    else
        warn "Render script failed; falling back to minimal configs."
    fi
fi

if [ "$RENDERED" -eq 0 ]; then
    info "Writing minimal default configs (no render script found yet) ..."
    cat > "$XRAY_CONFIG" <<EOF
{
  "log": {"loglevel": "warning"},
  "api": {"tag": "api", "services": ["HandlerService", "LoggerService", "StatsService"]},
  "stats": {},
  "inbounds": [
    {"tag": "api", "port": 10085, "listen": "127.0.0.1", "protocol": "dokodemo-door",
     "settings": {"address": "127.0.0.1"}},
    {"tag": "vless-reality", "port": 443, "protocol": "vless",
     "settings": {"clients": [], "decryption": "none"},
     "streamSettings": {"network": "tcp", "security": "reality",
       "realitySettings": {"show": false, "dest": "${REALITY_SNI}:443", "xver": 0,
         "serverNames": ["${REALITY_SNI}"],
         "privateKey": "${REALITY_PRIVATE_KEY}",
         "shortIds": ["${REALITY_SHORT_ID}"]}}},
    {"tag": "shadowsocks", "port": 8388, "protocol": "shadowsocks",
     "settings": {"method": "2022-blake3-aes-128-gcm",
       "password": "${SS_PASSWORD}", "network": "tcp,udp"}}
  ],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "blocked", "protocol": "blackhole"}
  ],
  "routing": {"rules": [
    {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"}
  ]}
}
EOF
    cat > "$SINGBOX_CONFIG" <<EOF
{
  "log": {"level": "warn"},
  "inbounds": [
    {"type": "hysteria2", "tag": "hy2", "listen": "::", "listen_port": 443,
     "users": [{"password": "${HY2_PASSWORD}"}],
     "tls": {"enabled": true, "server_name": "${CERT_CN}",
       "certificate_path": "/opt/sparky-manager/certs/fullchain.pem",
       "key_path": "/opt/sparky-manager/certs/privkey.pem"}}
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
    cat > /opt/sparky-manager/data/README-minimal-configs.txt <<'EOF'
Minimal configs (written by install.sh because no render script was
found yet). The panel re-renders /usr/local/etc/xray/config.json and
/etc/sing-box/config.json from its database whenever users or inbounds
change, so these files are only a starting point. Do not hand-edit them.
Default inbounds here: VLESS+Reality TCP 443, Shadowsocks 2022 TCP 8388
(Xray) and Hysteria2 UDP 443 (sing-box, self-signed cert). TLS inbounds
(TUIC, AnyTLS, Naive, ShadowTLS) are only created once a domain is set,
because they need a real certificate for a hostname.
EOF
fi
# Configs are group-writable by sparky-manager (0660) and live in group-writable
# directories: the panel (running as user sparky-manager) re-renders them from
# its database with an atomic rename, which needs write access to both the
# file and its directory. The cores run as root, so they can read them.
chmod 0660 "$XRAY_CONFIG" "$SINGBOX_CONFIG"
chown root:sparky-manager "$XRAY_CONFIG" "$SINGBOX_CONFIG"
chown root:sparky-manager /usr/local/etc/xray /etc/sing-box
chmod 0770 /usr/local/etc/xray /etc/sing-box

# WireGuard server config (native, not a core). Bring-up is best-effort:
# it needs the WireGuard kernel module, which may be absent in containers.
if [ ! -f "$WG_CONFIG" ]; then
    cat > "$WG_CONFIG" <<EOF
[Interface]
PrivateKey = ${WG_PRIVATE_KEY}
Address = 10.8.0.1/24
ListenPort = 51820
EOF
    chmod 0660 "$WG_CONFIG"
    chown root:sparky-manager "$WG_CONFIG"
fi
if ! wg show wg0 >/dev/null 2>&1; then
    wg-quick up wg0 2>/dev/null || \
        warn "Could not bring up wg0 (WireGuard kernel module may be missing). The config is written to ${WG_CONFIG}; start it with: wg-quick up wg0"
fi

# IP forwarding: the VPN servers (OpenVPN / ocserv / IKEv2 / WG /
# AmneziaWG) route client traffic, so the kernel must forward it.
# Persisted in /etc/sysctl.d/ so it survives a reboot.
if [ ! -f /etc/sysctl.d/99-sparky-manager.conf ]; then
    printf 'net.ipv4.ip_forward = 1\n' > /etc/sysctl.d/99-sparky-manager.conf
fi
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || \
    warn "Could not enable IPv4 forwarding (sysctl). VPN clients may not reach the internet."

# The OpenVPN auth script must be executable (openvpn runs it as root
# at connect time to check the username/password against the panel DB).
if [ -f /opt/sparky-manager/scripts/ovpn-auth.py ]; then
    chmod 0755 /opt/sparky-manager/scripts/ovpn-auth.py
fi

# Minimal server configs for the v12 protocols (the panel re-renders
# them from its database when users / inbounds change — these only
# exist so the services can start on a fresh install). Each is only
# written when its package is installed; a missing package only warns.
if command -v openvpn >/dev/null 2>&1 && [ ! -f /etc/openvpn/server/sparky-manager.conf ]; then
    cat > /etc/openvpn/server/sparky-manager.conf <<EOF
port 1194
proto udp
dev tun
ca /opt/sparky-manager/data/ca/ca-cert.pem
cert /opt/sparky-manager/data/ca/server-cert.pem
key /opt/sparky-manager/data/ca/server-key.pem
dh none
server 10.9.0.0 255.255.255.0
topology subnet
ifconfig-pool-persist /var/log/openvpn/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
keepalive 10 120
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
client-cert-not-required
username-as-common-name
auth-user-pass-verify /opt/sparky-manager/scripts/ovpn-auth.py via-file
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
log-append /var/log/openvpn/openvpn.log
verb 3
explicit-exit-notify 1
EOF
    chmod 0660 /etc/openvpn/server/sparky-manager.conf
    chown root:sparky-manager /etc/openvpn/server/sparky-manager.conf
fi
if command -v ocserv >/dev/null 2>&1; then
    if [ ! -f /etc/ocserv/ocserv.conf ]; then
        cat > /etc/ocserv/ocserv.conf <<EOF
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = 4433
udp-port = 4433
run-as-user = nobody
run-as-group = nogroup
server-cert = /opt/sparky-manager/data/ca/server-cert.pem
server-key = /opt/sparky-manager/data/ca/server-key.pem
ipv4-network = 10.10.10.0
ipv4-netmask = 255.255.255.0
dns = 1.1.1.1
dns = 1.0.0.1
route = default
cisco-client-compat = true
max-clients = 1024
use-occtl = true
socket-file = /run/ocserv/ocserv.sock
pid-file = /run/ocserv/ocserv.pid
EOF
        chmod 0660 /etc/ocserv/ocserv.conf
        chown root:sparky-manager /etc/ocserv/ocserv.conf
    fi
    if [ ! -f /etc/ocserv/ocpasswd ]; then
        : > /etc/ocserv/ocpasswd
        chmod 0660 /etc/ocserv/ocpasswd
        chown root:sparky-manager /etc/ocserv/ocpasswd
    fi
fi
if command -v swanctl >/dev/null 2>&1 && [ ! -f /etc/swanctl/swanctl.conf ]; then
    cat > /etc/swanctl/swanctl.conf <<EOF
pools {
    ipv4 {
        addrs = 10.20.0.0/24
        dns = 1.1.1.1, 1.0.0.1
    }
}

connections {
    remote-access {
        version = 2
        proposals = aes256-sha256-modp2048
        dpd_delay = 30s
        local {
            auth = pubkey
            certs = server-cert.pem
            id = ${CERT_CN}
        }
        remote {
            auth = eap-mschapv2
            eap_id = %any
        }
        children {
            tunnel {
                esp_proposals = aes256-sha256-modp2048
                local_ts = 0.0.0.0/0
                remote_ts = dynamic
                dpd_action = clear
                pools = ipv4
            }
        }
    }
}

secrets {
}
EOF
    chmod 0660 /etc/swanctl/swanctl.conf
    chown root:sparky-manager /etc/swanctl/swanctl.conf
fi
# AmneziaWG minimal config (fixed default obfuscation parameters;
# the panel generates fresh ones per inbound on first render).
# Best-effort: only when the tools are installed.
if command -v awg-quick >/dev/null 2>&1 && [ ! -f /etc/amnezia/amneziawg/awg0.conf ]; then
    cat > /etc/amnezia/amneziawg/awg0.conf <<EOF
[Interface]
PrivateKey = ${AWG_PRIVATE_KEY}
Address = 10.8.1.1/24
ListenPort = 51821
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 16
S3 = 17
S4 = 18
H1 = 100
H2 = 200
H3 = 300
H4 = 400
I1 = sparky1
I2 = sparky2
I3 = sparky3
I4 = sparky4
I5 = sparky5
# No HeaderProtectionKey here: the panel generates a fresh random
# one per inbound when it renders awg0.conf (it must match on
# server and client, and must never be a WireGuard key).
EOF
    chmod 0660 /etc/amnezia/amneziawg/awg0.conf
    chown root:sparky-manager /etc/amnezia/amneziawg/awg0.conf
    if ! awg show awg0 >/dev/null 2>&1; then
        awg-quick up awg0 2>/dev/null || \
            warn "Could not bring up awg0 (AmneziaWG kernel module may be missing). The config is written to /etc/amnezia/amneziawg/awg0.conf; start it with: awg-quick up awg0"
    fi
fi

# Validate both core configs before starting anything.
info "Validating core configs ..."
/usr/local/bin/xray run -test -c "$XRAY_CONFIG" || \
    die "Xray config validation failed: ${XRAY_CONFIG}"
/usr/local/bin/sing-box check -c "$SINGBOX_CONFIG" || \
    die "sing-box config validation failed: ${SINGBOX_CONFIG}"

# ---------------------------------------------------------------------------
# systemd units — copy from the repo's systemd/ when present, else write
# the same units inline as a fallback.
# ---------------------------------------------------------------------------
install_unit() {
    local name="$1"
    if [ -f "/opt/sparky-manager/systemd/${name}" ]; then
        cp "/opt/sparky-manager/systemd/${name}" "/etc/systemd/system/${name}"
    else
        warn "systemd/${name} not in the repo; writing the built-in fallback unit."
        case "$name" in
            sparky-manager.service) fallback_sparky_manager_unit > "/etc/systemd/system/${name}" ;;
            xray.service)      fallback_xray_unit > "/etc/systemd/system/${name}" ;;
            sing-box.service)  fallback_singbox_unit > "/etc/systemd/system/${name}" ;;
            *) die "No fallback unit for ${name}" ;;
        esac
    fi
    chmod 0644 "/etc/systemd/system/${name}"
}

fallback_sparky_manager_unit() {
    cat <<'EOF'
[Unit]
Description=sparky-manager — multi-core VPN panel (FastAPI)
After=network-online.target xray.service sing-box.service
Wants=network-online.target

[Service]
Type=simple
User=sparky-manager
Group=sparky-manager
WorkingDirectory=/opt/sparky-manager
EnvironmentFile=-/opt/sparky-manager/data/panel.env
# TLS is served by uvicorn itself: app.main does not configure SSL, so the
# self-signed certificate (or a later Let's Encrypt one in the same paths)
# is passed on the command line. The installer verifies
# https://127.0.0.1:<panel-port>/health, so these flags are load-bearing.
ExecStart=/opt/sparky-manager/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 2053 --ssl-certfile /opt/sparky-manager/certs/fullchain.pem --ssl-keyfile /opt/sparky-manager/certs/privkey.pem
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

fallback_xray_unit() {
    cat <<'EOF'
[Unit]
Description=Xray-core (sparky-manager)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -c /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

fallback_singbox_unit() {
    cat <<'EOF'
[Unit]
Description=sing-box (sparky-manager)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

info "Installing systemd units ..."
install_unit sparky-manager.service
install_unit xray.service
install_unit sing-box.service
# The shipped units default to port 2053; honour the chosen port.
sed -i "s/--port 2053/--port ${PANEL_PORT}/" /etc/systemd/system/sparky-manager.service
systemctl daemon-reload

# ---------------------------------------------------------------------------
# sparky-manager CLI wrapper (/usr/local/bin/sparky-manager): info / status /
# restart / backup. Non-interactive first; no hidden randomisation.
# ---------------------------------------------------------------------------
cat > /usr/local/bin/sparky-manager <<'EOF'
#!/usr/bin/env bash
# sparky-manager CLI — small wrapper installed by install.sh.
set -euo pipefail
cmd="${1:-info}"
case "$cmd" in
    info)
        if [ -f /root/sparky-manager-login.txt ]; then
            cat /root/sparky-manager-login.txt
        else
            echo "No login file found at /root/sparky-manager-login.txt."
            echo "Reinstall or check /opt/sparky-manager/data/panel.env for the panel port."
            exit 1
        fi
        ;;
    status)
        systemctl status sparky-manager xray sing-box --no-pager || true
        for svc in openvpn-server@sparky-manager ocserv strongswan awg-quick@awg0 wg-quick@wg0; do
            systemctl cat "$svc" >/dev/null 2>&1 && systemctl status "$svc" --no-pager || true
        done
        ;;
    restart)
        systemctl restart sparky-manager xray sing-box
        for svc in openvpn-server@sparky-manager ocserv strongswan; do
            systemctl cat "$svc" >/dev/null 2>&1 && systemctl restart "$svc" || true
        done
        echo "sparky-manager, xray and sing-box restarted."
        ;;
    backup)
        if [ -x /opt/sparky-manager/scripts/backup.sh ]; then
            exec /opt/sparky-manager/scripts/backup.sh "${2:-}"
        fi
        dest="${2:-/root/sparky-manager-backup-$(date +%F).tar.gz}"
        tar -czf "$dest" /opt/sparky-manager/data /usr/local/etc/xray/config.json /etc/sing-box/config.json
        echo "Backup written to: $dest"
        ;;
    *)
        echo "Usage: sparky-manager {info|status|restart|backup [PATH]}"
        exit 1
        ;;
esac
EOF
chmod 0755 /usr/local/bin/sparky-manager

# ---------------------------------------------------------------------------
# Start services and VERIFY before finishing.
# ---------------------------------------------------------------------------
info "Enabling and starting xray, sing-box and sparky-manager ..."
PANEL_WAS_ACTIVE=0
systemctl is-active --quiet sparky-manager 2>/dev/null && PANEL_WAS_ACTIVE=1
systemctl enable --now xray sing-box sparky-manager
# The v12 services (best-effort: a missing package only warns — the
# panel retries the service on the next config render).
for _svc in openvpn-server@sparky-manager ocserv strongswan; do
    systemctl enable --now "$_svc" 2>/dev/null || \
        warn "Could not start ${_svc} (its package may not be installed). The panel will retry it on the next config render."
done
# A regenerated certificate is only picked up when the panel
# restarts (enable --now does not restart a running service).
if [ "$CERT_REGENERATED" -eq 1 ] && [ "$PANEL_WAS_ACTIVE" -eq 1 ]; then
    systemctl restart sparky-manager
fi
# The Let's Encrypt IP certificate only lives ~6 days; acme.sh's cron
# renews it, but only if the cron daemon is running.
if [ "${LE_CERT_OK:-0}" -eq 1 ]; then
    systemctl enable --now cron 2>/dev/null || warn "Could not start cron — the trusted certificate will NOT auto-renew. Enable cron and re-run the installer."
fi

PANEL_OK=0
for _ in $(seq 1 30); do
    code="$(curl -ks -o /dev/null -w '%{http_code}' \
        "https://127.0.0.1:${PANEL_PORT}/${WEB_PATH}/health" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then
        PANEL_OK=1
        break
    fi
    sleep 1
done

FAILED=""
[ "$PANEL_OK" -eq 1 ] || FAILED="sparky-manager (health check https://127.0.0.1:${PANEL_PORT}/${WEB_PATH}/health did not return 200)"
systemctl is-active --quiet xray || FAILED="${FAILED} xray"
systemctl is-active --quiet sing-box || FAILED="${FAILED} sing-box"

if [ -n "$FAILED" ]; then
    warn "Verification failed for:${FAILED}"
    for svc in sparky-manager xray sing-box; do
        if ! systemctl is-active --quiet "$svc"; then
            echo "--- last 20 lines: ${svc} ---"
            journalctl -u "$svc" -n 20 --no-pager || true
        fi
    done
    if [ "$PANEL_OK" -eq 0 ]; then
        echo "--- last 20 lines: sparky-manager ---"
        journalctl -u sparky-manager -n 20 --no-pager || true
    fi
    die "Install verification failed. Fix the errors above and re-run the installer (it is idempotent)."
fi
info "Verification passed: panel answers 200 on /${WEB_PATH}/health, xray and sing-box are active."
# Soft check for the v12 services: warn, never fail the install.
for _svc in openvpn-server@sparky-manager ocserv strongswan; do
    if systemctl cat "$_svc" >/dev/null 2>&1; then
        systemctl is-active --quiet "$_svc" || \
            warn "${_svc} is not active; check: systemctl status ${_svc}"
    fi
done
if command -v ocserv >/dev/null 2>&1 && [ -f /etc/ocserv/ocserv.conf ]; then
    ocserv -t -c /etc/ocserv/ocserv.conf >/dev/null 2>&1 || \
        warn "ocserv config check failed; the panel will report the error on the next render."
fi

# ---------------------------------------------------------------------------
# Login box — printed and saved to /root/sparky-manager-login.txt (0600).
# ---------------------------------------------------------------------------
PANEL_URL="https://${SUBSCRIPTION_HOST}:${PANEL_PORT}/${WEB_PATH}"
umask 077
{
    echo "============================================================"
    echo "  sparky-manager installed"
    echo "============================================================"
    echo "  Panel:     ${PANEL_URL}"
    echo "  Username:  admin"
    echo "  Password:  ${ADMIN_PASSWORD}"
    echo ""
    echo "  Panel cert fingerprint (SHA256):"
    echo "  ${CERT_FINGERPRINT}"
    if printf '%s' "$CERT_ISSUER" | grep -qi "Let's Encrypt"; then
        echo ""
        echo "  Trusted Let's Encrypt certificate — no browser"
        echo "  warning. Valid until: ${CERT_EXPIRY}"
        echo "  (IP certificates last ~6 days and renew"
        echo "  automatically; keep TCP 80 open.)"
    elif [ -z "$DOMAIN" ]; then
        echo ""
        echo "  NOTE: no domain was given, so the panel uses a"
        echo "  SELF-SIGNED certificate. Your browser WILL warn"
        echo "  about it — that is expected. Check that the"
        echo "  fingerprint above matches before proceeding."
    else
        echo ""
        echo "  NOTE: the panel currently uses a self-signed"
        echo "  certificate. A real Let's Encrypt certificate is"
        echo "  available as an option in the panel settings."
    fi
    echo ""
    echo "  Default VPN (no domain needed):"
    echo "    VLESS+Reality  TCP 443  (SNI: ${REALITY_SNI})"
    echo "    Hysteria2      UDP 443"
    echo "    WireGuard      UDP 51820"
    echo "    Shadowsocks    TCP 8388"
    echo ""
    echo "  More protocols in the panel (create as inbounds):"
    echo "    OpenVPN        UDP 1194  (.ovpn file)"
    echo "    OpenConnect    TCP+UDP 4433  (AnyConnect profile)"
    echo "    AmneziaWG      UDP 51821  (vpn:// link + .conf)"
    echo "    IKEv2          UDP 500 + 4500  (.mobileconfig)"
    echo ""
    echo "  Panel logs: Logs page in the panel (data/logs/panel.log)."
    echo ""
    echo "  Subscriptions, QR codes and users are inside the panel."
    echo "  Reprint this anytime:  sudo sparky-manager info"
    echo "  Installed versions:    Xray ${XRAY_TAG}, sing-box ${SINGBOX_TAG}"
    echo "============================================================"
} > "$LOGIN_FILE"
chmod 0600 "$LOGIN_FILE"
cat "$LOGIN_FILE"
info "Login details saved to ${LOGIN_FILE}"
