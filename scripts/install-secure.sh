#!/bin/sh
# Security-hardened Open-Box installer for a4531613/Open-Box.
# Direct GitHub Releases only: no third-party mirror is trusted by default.

set -eu

REPO="a4531613/Open-Box"
INSTALL_ROOT="/opt/open-box"
MIN_FREE_KB=$((512 * 1024))
MIN_MEM_KB=450000

info() { echo "[open-box-secure] $*"; }
warn() { echo "[open-box-secure] warning: $*" >&2; }
die() { echo "[open-box-secure] error: $*" >&2; exit 1; }

safe_rm_rf() {
  target="$1"
  [ -n "$target" ] && [ "$target" != "/" ] || die "refusing unsafe rm -rf target"
  rm -rf -- "$target"
}

check_environment() {
  [ "$(id -u)" = "0" ] || die "run as root"
  [ -r /etc/openwrt_release ] || die "OpenWrt/ImmortalWrt not detected"

  raw_arch=$(uname -m 2>/dev/null || true)
  case "$raw_arch" in
    x86_64) ARCH="x64" ;;
    aarch64) ARCH="arm64" ;;
    *) die "unsupported CPU architecture: ${raw_arch:-unknown}" ;;
  esac

  mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || true)
  case "$mem_kb" in ''|*[!0-9]*) die "cannot read total memory" ;; esac
  [ "$mem_kb" -ge "$MIN_MEM_KB" ] || die "at least 512MB nominal RAM is required"

  dir="$INSTALL_ROOT"
  while [ ! -d "$dir" ] && [ "$dir" != "/" ]; do dir=$(dirname -- "$dir"); done
  free_kb=$(df -Pk "$dir" 2>/dev/null | awk 'END {print $4}')
  case "$free_kb" in ''|*[!0-9]*) die "cannot determine free storage" ;; esac
  [ "$free_kb" -ge "$MIN_FREE_KB" ] || die "at least 512MB free storage is required"

  if [ -e "$INSTALL_ROOT" ]; then
    leftover=""
    for entry in "$INSTALL_ROOT"/*; do
      [ -e "$entry" ] || continue
      [ "$(basename -- "$entry")" = "data" ] && continue
      leftover="yes"
      break
    done
    [ -z "$leftover" ] || die "existing installation found; use /opt/open-box/update.sh --direct instead"
  fi
}

DOWNLOADER=""
detect_downloader() {
  if command -v curl >/dev/null 2>&1; then
    DOWNLOADER="curl"
  elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER="wget"
  else
    die "curl or wget is required"
  fi
}

fetch_file() {
  url="$1"
  out="$2"
  case "$DOWNLOADER" in
    curl) curl -fL --proto '=https' --tlsv1.2 -o "$out" "$url" ;;
    wget) wget -q -O "$out" "$url" ;;
  esac
}

verify_checksum_file() {
  checksum_file="$1"
  asset="$2"
  hash=$(awk 'NR==1 {print $1}' "$checksum_file")
  name=$(awk 'NR==1 {print $2}' "$checksum_file")
  name=${name#\*}
  [ "$name" = "$asset" ] || die "checksum file references unexpected asset: $name"
  [ "${#hash}" = 64 ] || die "invalid SHA256 length"
  case "$hash" in *[!0-9a-fA-F]*) die "invalid SHA256 format" ;; esac
}

check_environment
detect_downloader

ASSET="open-box-linux-${ARCH}.tar.gz"
ASSET_URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
SHA_URL="${ASSET_URL}.sha256"
TMP_DL=$(mktemp -d "${TMPDIR:-/tmp}/open-box-secure.XXXXXX") || die "cannot create temp directory"
trap 'safe_rm_rf "$TMP_DL"' EXIT INT TERM

info "downloading checksum from GitHub official release endpoint"
round=0
while :; do
  round=$((round + 1))
  fetch_file "$SHA_URL" "$TMP_DL/$ASSET.sha256.pre" || die "failed to download checksum"
  verify_checksum_file "$TMP_DL/$ASSET.sha256.pre" "$ASSET"

  info "downloading $ASSET"
  fetch_file "$ASSET_URL" "$TMP_DL/$ASSET" || die "failed to download release asset"

  fetch_file "$SHA_URL" "$TMP_DL/$ASSET.sha256" || die "failed to re-download checksum"
  verify_checksum_file "$TMP_DL/$ASSET.sha256" "$ASSET"

  cmp -s "$TMP_DL/$ASSET.sha256.pre" "$TMP_DL/$ASSET.sha256" && break
  [ "$round" -lt 3 ] || die "release changed repeatedly during download; retry later"
  info "a newer release appeared during download; retrying"
done

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$TMP_DL" && sha256sum -c "$ASSET.sha256" >/dev/null) || die "SHA256 verification failed"
elif command -v shasum >/dev/null 2>&1; then
  (cd "$TMP_DL" && shasum -a 256 -c "$ASSET.sha256" >/dev/null) || die "SHA256 verification failed"
else
  die "sha256sum or shasum is required"
fi
info "SHA256 verified"

# Refuse a release that does not contain the hardening boundary. This protects against accidentally
# pointing the installer at an upstream/non-hardened artifact even if its own checksum is valid.
tar -tzf "$TMP_DL/$ASSET" | grep -qx 'panel/server/security-gateway.mjs' || \
  die "release is not a security-hardened build (security gateway missing)"
tar -tzf "$TMP_DL/$ASSET" | grep -qx 'openwrt/initd/openbox-panel' || \
  die "release is missing hardened OpenWrt service files"

meta=$(tar -xOzf "$TMP_DL/$ASSET" meta.json 2>/dev/null || true)
version=$(printf '%s\n' "$meta" | sed -n 's/.*"version" *: *"\([^"]*\)".*/\1/p' | head -n 1)
case "$version" in
  secure-v*) ;;
  *) die "release version is not a hardened secure-v* build: ${version:-unknown}" ;;
esac

mkdir -p "$INSTALL_ROOT"
if ! tar -xzf "$TMP_DL/$ASSET" -C "$INSTALL_ROOT"; then
  for entry in "$INSTALL_ROOT"/*; do
    [ -e "$entry" ] || continue
    [ "$(basename -- "$entry")" = "data" ] && continue
    safe_rm_rf "$entry"
  done
  die "failed to extract release; partial files were removed"
fi

chown -R 0:0 "$INSTALL_ROOT" 2>/dev/null || warn "could not reset ownership to root"
mkdir -p "$INSTALL_ROOT/data"
printf 'direct\n' > "$INSTALL_ROOT/data/channel"

cp "$INSTALL_ROOT/openwrt/initd/openbox" /etc/init.d/openbox
cp "$INSTALL_ROOT/openwrt/initd/openbox-panel" /etc/init.d/openbox-panel
chmod +x /etc/init.d/openbox /etc/init.d/openbox-panel

mkdir -p /www/luci-static/resources/view/openbox
cp "$INSTALL_ROOT/openwrt/luci/htdocs/luci-static/resources/view/openbox/status.js" \
  /www/luci-static/resources/view/openbox/status.js
mkdir -p /usr/share/luci/menu.d /usr/share/rpcd/acl.d
cp "$INSTALL_ROOT/openwrt/luci/root/usr/share/luci/menu.d/luci-app-openbox.json" \
  /usr/share/luci/menu.d/luci-app-openbox.json
cp "$INSTALL_ROOT/openwrt/luci/root/usr/share/rpcd/acl.d/luci-app-openbox.json" \
  /usr/share/rpcd/acl.d/luci-app-openbox.json

rm -rf /tmp/luci-*cache* 2>/dev/null || true
[ ! -x /etc/init.d/rpcd ] || /etc/init.d/rpcd restart >/dev/null 2>&1 || warn "rpcd restart failed"

/etc/init.d/openbox-panel enable || warn "failed to enable panel autostart"
/etc/init.d/openbox-panel restart || warn "panel restart returned a non-zero status"

lan_ip=$(uci -q get network.lan.ipaddr 2>/dev/null | tr ' ' '\n' | head -n 1 | cut -d/ -f1)
if [ -z "$lan_ip" ] && command -v ip >/dev/null 2>&1; then
  lan_ip=$(ip -4 -o addr show br-lan 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n 1)
fi

info "installed hardened Open-Box $version"
if [ -n "$lan_ip" ]; then
  info "panel: http://${lan_ip}:2026"
else
  info "panel: http://<LAN-IP>:2026"
fi
info "first visit requires setting a management password"
