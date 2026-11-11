#!/usr/bin/env bash
# vpn-panel installer — original work, written from scratch for this project.
#
# Installs vpn-panel (FastAPI panel + stock Xray-core + stock sing-box +
# native WireGuard) on Ubuntu 22.04/24.04/26.04 or Debian 12/13.
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
#   sudo bash install.sh [--yes] [--port PORT] [--domain example.com]
#                        [--reality-sni www.microsoft.com]
#                        [--admin-password 'secret']
#   curl -Ls https://raw.githubusercontent.com/SPARKY-CR/Zed-panel/main/install.sh | sudo bash
#   sudo bash install.sh --uninstall
#
# The repo URL above is a PLACEHOLDER until James creates/confirms the
# GitHub repo. Idempotent: safe to re-run; existing keys and the admin
# password are reused instead of regenerated.
#
# The panel port is randomised on a fresh install (like other panels),
# re-used on re-install, and always printed before the install proceeds
# (prompt, summary and login box); --yes accepts it, --port fixes it.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults (all printed before proceeding; overridable with flags)
# ---------------------------------------------------------------------------
REPO_URL="https://github.com/SPARKY-CR/Zed-panel.git"
PANEL_PORT=""        # empty = not given; resolved below (random on fresh install)
PORT_GIVEN=0         # 1 when --port is passed
DOMAIN=""
REALITY_SNI="www.microsoft.com"
ADMIN_PASSWORD=""
YES=0
UNINSTALL=0

XRAY_CONFIG="/usr/local/etc/xray/config.json"
SINGBOX_CONFIG="/etc/sing-box/config.json"
WG_CONFIG="/etc/wireguard/wg0.conf"
LOGIN_FILE="/root/vpn-panel-login.txt"

PANEL_VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# Log lines go to stderr so that command substitutions capturing a
# function's stdout (e.g. the release tag from download_core) stay clean.
info()  { printf '[vpn-panel] %s\n' "$*" >&2; }
warn()  { printf '[vpn-panel] WARNING: %s\n' "$*" >&2; }
die()   { printf '[vpn-panel] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: install.sh [OPTIONS]

Options:
  --yes                     Accept all defaults, ask nothing.
  --port PORT               Panel port (default: random free port
                            10000-60000 on a fresh install; the
                            previous port is reused on re-install).
  --domain DOMAIN           Domain for the panel (default: none — bare IP,
                            self-signed panel certificate).
  --reality-sni SNI         SNI for VLESS+Reality (default: www.microsoft.com).
  --admin-password PASS     Admin password (default: generated once and
                            printed in the login box).
  --uninstall               Stop services, back up data, remove vpn-panel.
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
    backup_file="/root/vpn-panel-backup-${stamp}.tar.gz"
    info "Backing up data and configs to ${backup_file} ..."
    local -a paths=()
    [ -d /opt/vpn-panel/data ] && paths+=("/opt/vpn-panel/data")
    [ -f /usr/local/etc/xray/config.json ] && paths+=("/usr/local/etc/xray/config.json")
    [ -f /etc/sing-box/config.json ] && paths+=("/etc/sing-box/config.json")
    [ -f /opt/vpn-panel/versions.env ] && paths+=("/opt/vpn-panel/versions.env")
    if [ "${#paths[@]}" -gt 0 ]; then
        tar -czf "$backup_file" "${paths[@]}" 2>/dev/null || \
            warn "Backup tarball may be incomplete; check ${backup_file}"
    else
        warn "Nothing to back up (no data or configs found)."
    fi

    info "Stopping services ..."
    systemctl stop vpn-panel xray sing-box 2>/dev/null || true
    systemctl disable vpn-panel xray sing-box 2>/dev/null || true
    if [ -f /etc/wireguard/wg0.conf ]; then
        wg-quick down wg0 2>/dev/null || true
    fi

    info "Removing files, units and binaries ..."
    rm -f /etc/systemd/system/vpn-panel.service \
          /etc/systemd/system/xray.service \
          /etc/systemd/system/sing-box.service
    systemctl daemon-reload || true
    rm -rf /opt/vpn-panel /usr/local/etc/xray /etc/sing-box
    rm -f /etc/wireguard/wg0.conf
    rm -f /usr/local/bin/xray /usr/local/bin/sing-box /usr/local/bin/vpn-panel
    if id vpn-panel >/dev/null 2>&1; then
        userdel vpn-panel 2>/dev/null || warn "Could not remove user vpn-panel."
    fi
    info "vpn-panel uninstalled. Backup kept at: ${backup_file}"
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

# Panel port: randomised on a fresh install (like other panels), re-used
# from panel.env on a re-install, --port always wins. The chosen port is
# printed in the prompt below, in the summary and in the login box.
if [ "$PORT_GIVEN" -eq 0 ]; then
    if [ -f /opt/vpn-panel/data/panel.env ]; then
        _saved_port="$(grep -E '^VPN_PANEL_PORT=' /opt/vpn-panel/data/panel.env | tail -n 1 | cut -d= -f2 | tr -d "'" || true)"
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

# ---------------------------------------------------------------------------
# Interactive prompts (all skippable with --yes / flags)
# ---------------------------------------------------------------------------
ask PANEL_PORT "Panel port" "$PANEL_PORT"
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

SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="$(curl -fsS -4 https://ifconfig.me 2>/dev/null || true)"
fi
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="127.0.0.1"
    warn "Could not detect the server IP; using 127.0.0.1 in the login box. Replace it with your real server IP."
fi

SUBSCRIPTION_HOST="${DOMAIN:-$SERVER_IP}"

info "Install summary:"
info "  Panel port:    ${PANEL_PORT}"
info "  Domain:        ${DOMAIN:-<none — bare IP, self-signed panel certificate>}"
info "  Server IP:     ${SERVER_IP}"
info "  Reality SNI:   ${REALITY_SNI}"
info "  Admin user:    admin"
info "  Admin pass:    ${ADMIN_PASSWORD:+<supplied>}"
if [ -z "$ADMIN_PASSWORD" ]; then
    info "  Admin pass:    <will be generated and printed in the login box>"
fi
info "  Default VPN:   VLESS+Reality TCP 443, Hysteria2 UDP 443, WireGuard UDP 51820"

# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------
info "Updating apt and installing packages ..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates git unzip \
    python3 python3-venv python3-pip \
    wireguard wireguard-tools nftables iproute2 openssl

# ---------------------------------------------------------------------------
# Directories and system user
# ---------------------------------------------------------------------------
info "Creating directories and the vpn-panel system user ..."
mkdir -p /opt/vpn-panel/app /opt/vpn-panel/data /opt/vpn-panel/certs \
         /usr/local/etc/xray /etc/sing-box /etc/wireguard
if ! id vpn-panel >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /opt/vpn-panel \
            --shell /usr/sbin/nologin vpn-panel
fi
chown -R vpn-panel:vpn-panel /opt/vpn-panel
chmod 0750 /opt/vpn-panel/data /opt/vpn-panel/certs
chmod 0755 /opt/vpn-panel/app

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
    PANEL_VERSION="${PANEL_VERSION:-1.0.0}"
fi

info "Copying the panel app to /opt/vpn-panel ..."
cp -a "${REPO_DIR}/app/." /opt/vpn-panel/app/
cp -a "${REPO_DIR}/requirements.txt" /opt/vpn-panel/requirements.txt
if [ -d "${REPO_DIR}/scripts" ]; then
    mkdir -p /opt/vpn-panel/scripts
    cp -a "${REPO_DIR}/scripts/." /opt/vpn-panel/scripts/
fi
if [ -d "${REPO_DIR}/systemd" ]; then
    mkdir -p /opt/vpn-panel/systemd
    cp -a "${REPO_DIR}/systemd/." /opt/vpn-panel/systemd/
fi
chown -R vpn-panel:vpn-panel /opt/vpn-panel/app /opt/vpn-panel/data

# ---------------------------------------------------------------------------
# Python virtualenv
# ---------------------------------------------------------------------------
info "Creating the Python virtualenv and installing dependencies ..."
if [ ! -x /opt/vpn-panel/venv/bin/python ]; then
    python3 -m venv /opt/vpn-panel/venv
fi
/opt/vpn-panel/venv/bin/pip install --disable-pip-version-check --quiet \
    --upgrade pip
/opt/vpn-panel/venv/bin/pip install --disable-pip-version-check \
    -r /opt/vpn-panel/requirements.txt

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
    printf 'VPN_PANEL_VERSION=%s\n' "$PANEL_VERSION"
    printf 'INSTALLED_AT=%s\n' "$(date -u +%FT%TZ)"
} > /opt/vpn-panel/versions.env
chmod 0644 /opt/vpn-panel/versions.env
info "Installed versions recorded in /opt/vpn-panel/versions.env"

# ---------------------------------------------------------------------------
# Secrets — reuse existing ones on re-install (idempotent), else generate.
# Stored in /opt/vpn-panel/data/install.env (0640, root:vpn-panel) so the
# panel service user can read it on first run; no other user can.
# Never printed to the terminal except the admin password in the login box.
# ---------------------------------------------------------------------------
INSTALL_ENV="/opt/vpn-panel/data/install.env"
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
if [ -z "${SS_PASSWORD:-}" ]; then
    # 2022-blake3-aes-128-gcm needs a base64 key of exactly 16 bytes —
    # a longer token is rejected by Xray ("bad key") and by sing-box.
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
    printf 'SS_PASSWORD=%s\n' "$(sq "$SS_PASSWORD")"
    printf 'HY2_PASSWORD=%s\n' "$(sq "$HY2_PASSWORD")"
} > "$INSTALL_ENV"
chmod 0640 "$INSTALL_ENV"
chown root:vpn-panel "$INSTALL_ENV"

# Panel runtime settings for the app (read by app/config.py via env vars).
# The secret values below are ALSO in install.env; they are repeated here
# as VPN_PANEL_* variables so the app can seed its database from them on
# first run (admin password, Reality keypair, WireGuard keys) instead of
# generating different ones. The app must read these on first run — see
# the bootstrap note in the install report if it does not yet.
{
    printf 'VPN_PANEL_HOME=%s\n' "$(sq "/opt/vpn-panel")"
    printf 'VPN_PANEL_PORT=%s\n' "$(sq "$PANEL_PORT")"
    printf 'VPN_PANEL_HOST=%s\n' "$(sq "0.0.0.0")"
    printf 'VPN_PANEL_DOMAIN=%s\n' "$(sq "$DOMAIN")"
    printf 'VPN_PANEL_SUBSCRIPTION_HOST=%s\n' "$(sq "$SUBSCRIPTION_HOST")"
    printf 'VPN_PANEL_REALITY_SNI=%s\n' "$(sq "$REALITY_SNI")"
    printf 'VPN_PANEL_ADMIN_PASSWORD=%s\n' "$(sq "$ADMIN_PASSWORD")"
    printf 'VPN_PANEL_REALITY_PRIVATE_KEY=%s\n' "$(sq "$REALITY_PRIVATE_KEY")"
    printf 'VPN_PANEL_REALITY_PUBLIC_KEY=%s\n' "$(sq "$REALITY_PUBLIC_KEY")"
    printf 'VPN_PANEL_REALITY_SHORT_ID=%s\n' "$(sq "$REALITY_SHORT_ID")"
    printf 'VPN_PANEL_WG_PRIVATE_KEY=%s\n' "$(sq "$WG_PRIVATE_KEY")"
    printf 'VPN_PANEL_WG_PUBLIC_KEY=%s\n' "$(sq "$WG_PUBLIC_KEY")"
} > /opt/vpn-panel/data/panel.env
chmod 0640 /opt/vpn-panel/data/panel.env
chown root:vpn-panel /opt/vpn-panel/data/panel.env

# ---------------------------------------------------------------------------
# Panel certificate — self-signed when no domain is given (DESIGN §7).
# The browser WILL warn about it; the fingerprint is printed in the
# login box so it can be checked. With a domain, this self-signed cert
# is only an interim: a real Let's Encrypt certificate is an option in
# the panel settings afterwards, never a requirement at install time.
# ---------------------------------------------------------------------------
CERT_CN="${DOMAIN:-$SERVER_IP}"
if [ ! -f /opt/vpn-panel/certs/fullchain.pem ] || [ ! -f /opt/vpn-panel/certs/privkey.pem ]; then
    info "Generating a self-signed panel certificate (365 days, CN=${CERT_CN}) ..."
    if [ -n "$DOMAIN" ]; then
        SAN="DNS:${DOMAIN},IP:${SERVER_IP}"
    else
        SAN="IP:${SERVER_IP}"
    fi
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /opt/vpn-panel/certs/privkey.pem \
        -out /opt/vpn-panel/certs/fullchain.pem \
        -days 365 -subj "/CN=${CERT_CN}" \
        -addext "subjectAltName=${SAN}" 2>/dev/null
    chmod 0600 /opt/vpn-panel/certs/privkey.pem
    chmod 0644 /opt/vpn-panel/certs/fullchain.pem
    chown root:vpn-panel /opt/vpn-panel/certs/privkey.pem /opt/vpn-panel/certs/fullchain.pem
else
    info "Keeping the existing panel certificate."
fi
CERT_FINGERPRINT="$(openssl x509 -noout -fingerprint -sha256 \
    -in /opt/vpn-panel/certs/fullchain.pem | cut -d'=' -f2)"

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
    /opt/vpn-panel/venv/bin/python -c '
import json, sys
try:
    cfg = json.load(open("/opt/vpn-panel/data/rendered/xray.json"))
except Exception:
    sys.exit(1)
tags = [i.get("tag") for i in cfg.get("inbounds", []) if isinstance(i, dict)]
sys.exit(0 if any(t and t != "api" for t in tags) else 1)
'
}

RENDERED=0
if [ -f /opt/vpn-panel/scripts/render_configs.py ]; then
    info "Rendering configs with the panel's render script ..."
    if VPN_PANEL_HOME=/opt/vpn-panel /opt/vpn-panel/venv/bin/python \
            /opt/vpn-panel/scripts/render_configs.py; then
        if _rendered_has_vpn_inbounds; then
            # The render script writes to data/rendered/ — copy the
            # outputs to the live config paths the cores actually read.
            cp /opt/vpn-panel/data/rendered/xray.json "$XRAY_CONFIG"
            cp /opt/vpn-panel/data/rendered/sing-box.json "$SINGBOX_CONFIG"
            if [ -f /opt/vpn-panel/data/rendered/wg0.conf ]; then
                cp /opt/vpn-panel/data/rendered/wg0.conf "$WG_CONFIG"
                chmod 0660 "$WG_CONFIG"
                chown root:vpn-panel "$WG_CONFIG"
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
       "certificate_path": "/opt/vpn-panel/certs/fullchain.pem",
       "key_path": "/opt/vpn-panel/certs/privkey.pem"}}
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
    cat > /opt/vpn-panel/data/README-minimal-configs.txt <<'EOF'
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
# Configs are group-writable by vpn-panel (0660) and live in group-writable
# directories: the panel (running as user vpn-panel) re-renders them from
# its database with an atomic rename, which needs write access to both the
# file and its directory. The cores run as root, so they can read them.
chmod 0660 "$XRAY_CONFIG" "$SINGBOX_CONFIG"
chown root:vpn-panel "$XRAY_CONFIG" "$SINGBOX_CONFIG"
chown root:vpn-panel /usr/local/etc/xray /etc/sing-box
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
    chown root:vpn-panel "$WG_CONFIG"
fi
if ! wg show wg0 >/dev/null 2>&1; then
    wg-quick up wg0 2>/dev/null || \
        warn "Could not bring up wg0 (WireGuard kernel module may be missing). The config is written to ${WG_CONFIG}; start it with: wg-quick up wg0"
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
    if [ -f "/opt/vpn-panel/systemd/${name}" ]; then
        cp "/opt/vpn-panel/systemd/${name}" "/etc/systemd/system/${name}"
    else
        warn "systemd/${name} not in the repo; writing the built-in fallback unit."
        case "$name" in
            vpn-panel.service) fallback_vpn_panel_unit > "/etc/systemd/system/${name}" ;;
            xray.service)      fallback_xray_unit > "/etc/systemd/system/${name}" ;;
            sing-box.service)  fallback_singbox_unit > "/etc/systemd/system/${name}" ;;
            *) die "No fallback unit for ${name}" ;;
        esac
    fi
    chmod 0644 "/etc/systemd/system/${name}"
}

fallback_vpn_panel_unit() {
    cat <<'EOF'
[Unit]
Description=vpn-panel — multi-core VPN panel (FastAPI)
After=network-online.target xray.service sing-box.service
Wants=network-online.target

[Service]
Type=simple
User=vpn-panel
Group=vpn-panel
WorkingDirectory=/opt/vpn-panel
EnvironmentFile=-/opt/vpn-panel/data/panel.env
# TLS is served by uvicorn itself: app.main does not configure SSL, so the
# self-signed certificate (or a later Let's Encrypt one in the same paths)
# is passed on the command line. The installer verifies
# https://127.0.0.1:<panel-port>/health, so these flags are load-bearing.
ExecStart=/opt/vpn-panel/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 2053 --ssl-certfile /opt/vpn-panel/certs/fullchain.pem --ssl-keyfile /opt/vpn-panel/certs/privkey.pem
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

fallback_xray_unit() {
    cat <<'EOF'
[Unit]
Description=Xray-core (vpn-panel)
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
Description=sing-box (vpn-panel)
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
install_unit vpn-panel.service
install_unit xray.service
install_unit sing-box.service
# The shipped units default to port 2053; honour the chosen port.
sed -i "s/--port 2053/--port ${PANEL_PORT}/" /etc/systemd/system/vpn-panel.service
systemctl daemon-reload

# ---------------------------------------------------------------------------
# vpn-panel CLI wrapper (/usr/local/bin/vpn-panel): info / status /
# restart / backup. Non-interactive first; no hidden randomisation.
# ---------------------------------------------------------------------------
cat > /usr/local/bin/vpn-panel <<'EOF'
#!/usr/bin/env bash
# vpn-panel CLI — small wrapper installed by install.sh.
set -euo pipefail
cmd="${1:-info}"
case "$cmd" in
    info)
        if [ -f /root/vpn-panel-login.txt ]; then
            cat /root/vpn-panel-login.txt
        else
            echo "No login file found at /root/vpn-panel-login.txt."
            echo "Reinstall or check /opt/vpn-panel/data/panel.env for the panel port."
            exit 1
        fi
        ;;
    status)
        systemctl status vpn-panel xray sing-box --no-pager || true
        ;;
    restart)
        systemctl restart vpn-panel xray sing-box
        echo "vpn-panel, xray and sing-box restarted."
        ;;
    backup)
        if [ -x /opt/vpn-panel/scripts/backup.sh ]; then
            exec /opt/vpn-panel/scripts/backup.sh "${2:-}"
        fi
        dest="${2:-/root/vpn-panel-backup-$(date +%F).tar.gz}"
        tar -czf "$dest" /opt/vpn-panel/data /usr/local/etc/xray/config.json /etc/sing-box/config.json
        echo "Backup written to: $dest"
        ;;
    *)
        echo "Usage: vpn-panel {info|status|restart|backup [PATH]}"
        exit 1
        ;;
esac
EOF
chmod 0755 /usr/local/bin/vpn-panel

# ---------------------------------------------------------------------------
# Start services and VERIFY before finishing.
# ---------------------------------------------------------------------------
info "Enabling and starting xray, sing-box and vpn-panel ..."
systemctl enable --now xray sing-box vpn-panel

PANEL_OK=0
for _ in $(seq 1 30); do
    code="$(curl -ks -o /dev/null -w '%{http_code}' \
        "https://127.0.0.1:${PANEL_PORT}/health" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then
        PANEL_OK=1
        break
    fi
    sleep 1
done

FAILED=""
[ "$PANEL_OK" -eq 1 ] || FAILED="vpn-panel (health check https://127.0.0.1:${PANEL_PORT}/health did not return 200)"
systemctl is-active --quiet xray || FAILED="${FAILED} xray"
systemctl is-active --quiet sing-box || FAILED="${FAILED} sing-box"

if [ -n "$FAILED" ]; then
    warn "Verification failed for:${FAILED}"
    for svc in vpn-panel xray sing-box; do
        if ! systemctl is-active --quiet "$svc"; then
            echo "--- last 20 lines: ${svc} ---"
            journalctl -u "$svc" -n 20 --no-pager || true
        fi
    done
    if [ "$PANEL_OK" -eq 0 ]; then
        echo "--- last 20 lines: vpn-panel ---"
        journalctl -u vpn-panel -n 20 --no-pager || true
    fi
    die "Install verification failed. Fix the errors above and re-run the installer (it is idempotent)."
fi
info "Verification passed: panel answers 200 on /health, xray and sing-box are active."

# ---------------------------------------------------------------------------
# Login box — printed and saved to /root/vpn-panel-login.txt (0600).
# ---------------------------------------------------------------------------
PANEL_URL="https://${SUBSCRIPTION_HOST}:${PANEL_PORT}"
umask 077
{
    echo "============================================================"
    echo "  vpn-panel installed"
    echo "============================================================"
    echo "  Panel:     ${PANEL_URL}"
    echo "  Username:  admin"
    echo "  Password:  ${ADMIN_PASSWORD}"
    echo ""
    echo "  Panel cert fingerprint (SHA256):"
    echo "  ${CERT_FINGERPRINT}"
    if [ -z "$DOMAIN" ]; then
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
    echo "  Subscriptions, QR codes and users are inside the panel."
    echo "  Reprint this anytime:  sudo vpn-panel info"
    echo "  Installed versions:    Xray ${XRAY_TAG}, sing-box ${SINGBOX_TAG}"
    echo "============================================================"
} > "$LOGIN_FILE"
chmod 0600 "$LOGIN_FILE"
cat "$LOGIN_FILE"
info "Login details saved to ${LOGIN_FILE}"
