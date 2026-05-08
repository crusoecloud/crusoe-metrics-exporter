#!/bin/sh
# Compile all eBPF .c files in this directory for the specified architectures.
# Usage: ./ebpf/compile.sh [--arch <amd64|arm64>] [--outdir <dir>]
# If --arch is not specified, compiles for both amd64 and arm64.
# Output files are named <name>_<arch>.o (or <name>.o if a single arch is given).

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CLANG="${CLANG:-clang}"
OUTDIR=""
ARCHES=""

while [ $# -gt 0 ]; do
    case "$1" in
        --arch)  ARCHES="$ARCHES $2"; shift 2 ;;
        --outdir) OUTDIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Default to both architectures
if [ -z "$ARCHES" ]; then
    ARCHES="amd64 arm64"
fi

arch_define() {
    case "$1" in
        amd64) echo "__TARGET_ARCH_x86" ;;
        arm64) echo "__TARGET_ARCH_arm64" ;;
        *) echo "Unsupported architecture: $1" >&2; exit 1 ;;
    esac
}

# Determine if we should suffix output files with the arch
MULTI_ARCH=$(echo $ARCHES | wc -w | tr -d ' ')

for src in "$SCRIPT_DIR"/*.c; do
    [ -f "$src" ] || continue
    name="$(basename "$src" .c)"

    for arch in $ARCHES; do
        define="$(arch_define "$arch")"

        if [ "$MULTI_ARCH" -gt 1 ]; then
            outname="${name}_${arch}.o"
        else
            outname="${name}.o"
        fi

        dest="${OUTDIR:-$SCRIPT_DIR}/$outname"
        mkdir -p "$(dirname "$dest")"

        echo "Compiling $name for $arch -> $dest"
        $CLANG -g -O2 -target bpf -D"$define" \
            -I"$REPO_ROOT" \
            -c "$src" -o "$dest"
    done
done

echo "eBPF compilation complete."
