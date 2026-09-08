#!/bin/sh
# Fail CI if upstream dashboard promotion or common advertising/community hooks return to runtime UI.
# Legal attribution (LICENSE/NOTICE) and functional network dependencies are intentionally out of scope.
set -eu

fail=0

forbidden_source() {
  pattern="$1"
  description="$2"
  if grep -R -n -E "$pattern" panel/src \
    --exclude='en.ts' --exclude='zh.ts' --exclude='zh-tw.ts' 2>/dev/null; then
    echo "[promotion-audit] forbidden runtime source: $description" >&2
    fail=1
  fi
}

forbidden_source 'AnGe-ClashBoard|basedOnZashboard|fetchIsUIUpdateAvailable|upgradeUIAPI' \
  'upstream dashboard branding or self-update channel'
forbidden_source 't\.me/|telegram\.me/|discord\.gg/|buymeacoffee|ko-fi|patreon|sponsor|donat(e|ion)|赞助|捐赠|广告' \
  'advertising, donation, sponsor or community promotion link/text'

# The hardened runtime may display dependency names/versions, but settings components must not
# turn those names into promotional GitHub links.
if grep -R -n -E 'github\.com/(sagernet/sing-box|metacubex/mihomo|liandu2024/AnGe-ClashBoard)' \
  panel/src/components panel/src/views 2>/dev/null; then
  echo '[promotion-audit] forbidden promotional repository link in runtime UI' >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo '[promotion-audit] FAILED' >&2
  exit 1
fi

echo '[promotion-audit] PASS: no runtime advertising/promotion hooks found'
