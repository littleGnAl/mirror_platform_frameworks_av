#!/bin/bash

# =============================================================================
# DOCUMENTATION GENERATION
# =============================================================================

if [ -z "$ANDROID_BUILD_TOP" ]; then
  echo "error: Android build is not set up. Run this command after lunch." >&2
  exit 2
fi

OUT_DIR=$ANDROID_BUILD_TOP/out

# Codec 2.0 source and target paths
C2_ROOT=$(dirname "$0")
C2_DOCS_ROOT=$OUT_DIR/target/common/docs/codec2
C2_OUT_TEMP=$ANDROID_PRODUCT_OUT/gen/ETC/Codec2-docs_intermediates

# Doxygen path
DOXY=$(which doxygen)
DOXY_MAC="/Applications/Doxygen.app/Contents/Resources/doxygen"
if [ -z "$DOXY" -a -x "$DOXY_MAC" ]; then
  DOXY=$DOXY_MAC
fi

if [ -z "$DOXY" ]; then
  echo "error: doxygen is not available" >&2
  exit 2
fi

# Create doxygen config
# ---------------------
gen_doxy() {
  local variant=$1
  local variant_lc=$(echo $variant | tr A-Z a-z)
  mkdir -p $C2_OUT_TEMP
  if [ "$variant_lc" == "api" ]; then
    # only document include directory, no internal sections
    sed 's/\(^INPUT *=.*\)/\1core\/include\//;
      s/\(^INTERNAL_DOCS *= *\).*/\1NO/;
      s/\(^ENABLED_SECTIONS *=.*\)INTERNAL\(.*\).*/\1\2/;
      s:\(^OUTPUT_DIRECTORY *= \)out\(.*\)api:\1'$OUT_DIR'\2'$variant_lc':;' \
      $C2_ROOT/docs/doxygen.config > $C2_OUT_TEMP/doxy-$variant_lc.config

    ls -la $C2_OUT_TEMP/doxy-$variant_lc.config
  else
    sed 's:\(^OUTPUT_DIRECTORY *= \)out\(.*\)api:\1'$OUT_DIR'\2'$variant_lc':;' \
      $C2_ROOT/docs/doxygen.config > $C2_OUT_TEMP/doxy-$variant_lc.config
  fi

  echo $variant docs are building in $C2_DOCS_ROOT/$variant_lc
  rm -rf $C2_DOCS_ROOT/$variant_lc
  mkdir -p $C2_DOCS_ROOT/$variant_lc
  pushd $ANDROID_BUILD_TOP
  $DOXY $C2_OUT_TEMP/doxy-$variant_lc.config
  popd
}

usage() {
  echo "usage: $(basename "$0") [target]"
  echo "  where target can be one of:"
  echo "    all:      build both API and internal docs (default)"
  echo "    api:      build API docs only"
  echo "    internal: build internal docs which include implementation details"
}

TARGET=${1:-all}
case "$TARGET" in
  api) gen_doxy API;;
  internal) gen_doxy Internal;;
  all) gen_doxy API; gen_doxy Internal;;
  -h) usage; exit 0;;
  *) echo "unknown target '$TARGET'" >&2; usage; exit 2;;
esac
