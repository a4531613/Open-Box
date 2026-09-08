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

# High-confidence upstream dashboard promotion/self-update code: block anywhere in runtime source.
forbidden_source 'AnGe-ClashBoard|basedOnZashboard|fetchIsUIUpdateAvailable|upgradeUIAPI' \
  'upstream dashboard branding or self-update channel'

# Community/donation destinations are promotional regardless of whether they appear in a template
# or a helper. Do not match the generic Chinese word "广告" here: subscription code legitimately
# contains comments and filters for removing airport announcement/ad nodes.
forbidden_source 't\.me/|telegram\.me/|discord\.gg/|buymeacoffee|ko-fi|patreon' \
  'community or donation promotion link'

# Human-visible advertising/donation copy belongs in Vue UI. Restrict the generic wording check to
# templates/components so anti-ad implementation comments do not become false positives.
if grep -R -n -E '赞助|捐赠|广告|sponsor|donat(e|ion)' panel/src \
  --include='*.vue' 2>/dev/null; then
  echo '[promotion-audit] forbidden advertising/donation text in runtime UI' >&2
  fail=1
fi

# Localized donation/sponsor copy is also visible even though locale resources are TypeScript.
# Keep this high confidence and intentionally do not match the generic word "广告".
if grep -R -n -E '赞助|捐赠|sponsor|donat(e|ion)|buymeacoffee|ko-fi|patreon' panel/src/i18n 2>/dev/null; then
  echo '[promotion-audit] forbidden advertising/donation copy in locale resources' >&2
  fail=1
fi

# The hardened runtime may display dependency names/versions, but components/views must not turn
# those names into promotional repository links or branded dashboard references.
if grep -R -n -E 'github\.com/(sagernet/sing-box|metacubex/mihomo|liandu2024/AnGe-ClashBoard)' \
  panel/src/components panel/src/views 2>/dev/null; then
  echo '[promotion-audit] forbidden promotional repository link in runtime UI' >&2
  fail=1
fi

if grep -R -n -E 'metacubex\.jpg|sing-box\.svg' panel/src/components panel/src/views 2>/dev/null; then
  echo '[promotion-audit] forbidden third-party brand logo in runtime UI' >&2
  fail=1
fi

# Overview is the landing page. Keep its top control bar product-neutral: no backend branding,
# external links, or version badge may be reintroduced above the actual dashboard content.
if grep -n -E 'BackendVersion|href=|https?://' panel/src/components/sidebar/OverviewCtrl.vue 2>/dev/null; then
  echo '[promotion-audit] forbidden branding or external link in overview top bar' >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo '[promotion-audit] FAILED' >&2
  exit 1
fi

echo '[promotion-audit] PASS: no runtime advertising/promotion hooks found'
