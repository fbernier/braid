#!/usr/bin/env bash
# Build and install `brd`.
#
# `libghostty-vt-sys` builds Ghostty from a pinned commit whose `build.zig.zon`
# names `minimum_zig_version = "0.16.0"`. Zig's check requires an exact major and
# minor with a patch at or above the floor, so any 0.16.x host toolchain is used
# as-is; otherwise one is fetched into a cache directory and put on PATH for this
# build alone.

set -euo pipefail

ZIG_VERSION="0.16.0"
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${BRD_PREFIX:-$HOME/.local/bin}"
ZIG_CACHE="${BRD_ZIG_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/braid/zig}"
ZIG_SYSTEM_DIR="${GHOSTTY_ZIG_SYSTEM_DIR:-}"

usage() {
    cat <<EOF
usage: install.sh [--prefix DIR] [--zig-dir DIR] [--zig-system-dir DIR]

  --prefix DIR          where to install brd    (default: $HOME/.local/bin)
  --zig-dir DIR         cache for a fetched Zig (default: \${XDG_CACHE_HOME:-\$HOME/.cache}/braid/zig)
  --zig-system-dir DIR  resolve Ghostty's Zig packages from DIR instead of
                        letting Zig fetch them. Also read from
                        GHOSTTY_ZIG_SYSTEM_DIR. Fill DIR on a host that can
                        reach the package hosts by running
                        \`zig build --fetch=all\` in a Ghostty checkout, which
                        writes its \`zig-pkg\`; copy that here.

A host \`zig\` is used when its major and minor match $ZIG_VERSION. Otherwise that
release is downloaded, checksum-verified, and used for this build alone; it is
never installed system-wide.

Ghostty's source is fetched by \`libghostty-vt-sys\`'s build script at the commit
that crate pins, so the build needs network access to github.com.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --zig-dir) ZIG_CACHE="${2:?--zig-dir needs a directory}"; shift 2 ;;
        --zig-system-dir) ZIG_SYSTEM_DIR="${2:?--zig-system-dir needs a directory}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'install.sh: unknown argument %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
note() { printf '==> %s\n' "$*"; }
warn() { printf 'install.sh: %s\n' "$*" >&2; }

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required but not on PATH"; }

# Zig names its releases <arch>-<os>, which is neither uname's spelling nor
# Rust's triple.
zig_platform() {
    local os arch
    case "$(uname -s)" in
        Linux) os="linux" ;;
        Darwin) os="macos" ;;
        *) die "unsupported OS $(uname -s); build manually with Zig $ZIG_VERSION on PATH" ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) die "unsupported architecture $(uname -m); build manually with Zig $ZIG_VERSION on PATH" ;;
    esac
    printf '%s-%s' "$arch" "$os"
}

# Pinned rather than fetched from the release index: an install script that
# downloads a compiler without checking what it got is a supply-chain hole.
zig_sha256() {
    case "$1" in
        x86_64-linux)  printf '70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00' ;;
        aarch64-linux) printf 'ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17' ;;
        x86_64-macos)  printf '0387557ed1877bc6a2e1802c8391953baddba76081876301c522f52977b52ba7' ;;
        aarch64-macos) printf 'b23d70deaa879b5c2d486ed3316f7eaa53e84acf6fc9cc747de152450d401489' ;;
        *) die "no pinned checksum for $1" ;;
    esac
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

download() {
    local url="$1" out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$out" "$url"
    else
        wget -q --https-only -O "$out" "$url"
    fi
}

# Ghostty's `requireZig` compares major and minor exactly and accepts any patch
# at or above the floor, so a host 0.16.1 is fine and 0.15.x is not.
zig_ok() {
    [ -x "$1" ] || return 1
    local reported major minor patch
    reported="$("$1" version 2>/dev/null)" || return 1
    # A dev build reports 0.16.0-dev.164+bc7955306; only the release part is compared.
    IFS='.-' read -r major minor patch _ <<<"$reported"
    [ "$major.$minor" = "${ZIG_VERSION%.*}" ] || return 1
    case "$patch" in ''|*[!0-9]*) return 1 ;; esac
    [ "$patch" -ge "${ZIG_VERSION##*.}" ]
}

# Sets ZIG_DIR to the directory holding a usable zig, fetching one if needed.
# The directory matters, not the binary: zig resolves its own `lib/` relative to
# argv[0], so the tree cannot be split up.
#
# It assigns rather than printing because bash disables errexit inside command
# substitution: as `$(ensure_zig)` a failed download or extraction would be
# swallowed and misreported as a bad Zig two lines later.
ensure_zig() {
    local host_zig platform dir archive staging got want
    host_zig="$(command -v zig 2>/dev/null || true)"
    if [ -n "$host_zig" ] && zig_ok "$host_zig"; then
        note "using host Zig $("$host_zig" version) ($host_zig)"
        ZIG_DIR="$(dirname -- "$host_zig")"
        return
    fi
    if [ -n "$host_zig" ]; then
        note "host Zig is $("$host_zig" version 2>/dev/null || echo unknown); Ghostty needs ${ZIG_VERSION%.*}.x"
    fi

    platform="$(zig_platform)"
    dir="$ZIG_CACHE/zig-$platform-$ZIG_VERSION"
    if zig_ok "$dir/zig"; then
        note "using cached Zig $("$dir/zig" version) ($dir/zig)"
        ZIG_DIR="$dir"
        return
    fi

    need tar
    # tar delegates .xz to a separate binary, and its failure message names
    # neither xz nor the archive.
    need xz
    command -v curl >/dev/null 2>&1 || need wget
    command -v sha256sum >/dev/null 2>&1 || need shasum

    # Cleanup is explicit rather than a RETURN trap: without `set -T` such a
    # trap leaks past this function and fires on every later return, reading an
    # out-of-scope variable under `set -u`.
    archive="$(mktemp -t "zig-$ZIG_VERSION-XXXXXX.tar.xz")"
    note "downloading Zig $ZIG_VERSION for $platform"
    if ! download "https://ziglang.org/download/$ZIG_VERSION/zig-$platform-$ZIG_VERSION.tar.xz" "$archive"; then
        rm -f "$archive"
        die "cannot download Zig $ZIG_VERSION for $platform"
    fi

    want="$(zig_sha256 "$platform")"
    got="$(sha256_of "$archive")"
    if [ "$got" != "$want" ]; then
        rm -f "$archive"
        die "Zig checksum mismatch: expected $want, got $got"
    fi

    mkdir -p "$ZIG_CACHE"
    rm -rf "$dir"
    # Extract beside the target and rename, so an interrupted run never leaves a
    # partial tree that the next one would trust.
    staging="$(mktemp -d "$ZIG_CACHE/.staging-XXXXXX")"
    if ! tar -xJf "$archive" -C "$staging"; then
        rm -f "$archive"
        rm -rf "$staging"
        die "cannot extract Zig archive"
    fi
    rm -f "$archive"
    mv "$staging/zig-$platform-$ZIG_VERSION" "$dir"
    rmdir "$staging"

    zig_ok "$dir/zig" || die "extracted Zig does not report $ZIG_VERSION"
    note "Zig $("$dir/zig" version) ready at $dir/zig"
    ZIG_DIR="$dir"
}

# Every `brd` on this PATH, in order. An SSH login resolves `brd --server`
# through its own PATH, so any stale copy is a candidate, and one speaking an
# older protocol fails as "stream ended before a complete frame" with the
# version named nowhere.
report_path_conflicts() {
    local installed="$1" dir candidate known conflict=0
    local -a dirs=() seen=()
    # Scoped to the read: joining `seen` for the duplicate test below needs the
    # default IFS back, and PATH routinely lists the same directory twice.
    IFS=: read -r -a dirs <<< "$PATH"
    for dir in "${dirs[@]}"; do
        [ -n "$dir" ] || dir="."
        candidate="$dir/brd"
        [ -f "$candidate" ] && [ -x "$candidate" ] || continue
        for known in ${seen[@]+"${seen[@]}"}; do
            [ "$known" = "$candidate" ] && continue 2
        done
        seen+=("$candidate")
        cmp -s "$candidate" "$installed" || conflict=1
    done

    [ "${#seen[@]}" -gt 1 ] || return 0

    if [ "$conflict" -eq 0 ]; then
        note "${#seen[@]} copies of brd on PATH, all this build:"
        printf '    %s\n' "${seen[@]}"
        return 0
    fi

    printf '\n'
    warn "more than one brd is on PATH:"
    for candidate in "${seen[@]}"; do
        if cmp -s "$candidate" "$installed"; then
            printf '    %s  (this build)\n' "$candidate" >&2
        else
            printf '    %s  (differs)\n' "$candidate" >&2
        fi
    done
    warn "a login shell picks one by its own PATH order, which need not match this one."
    warn "install over the stale copies too, or remove them:"
    for candidate in "${seen[@]}"; do
        cmp -s "$candidate" "$installed" || printf '        install -m 0755 %s %s\n' "$installed" "$candidate" >&2
    done
}

need cargo
need git

ensure_zig
export PATH="$ZIG_DIR:$PATH"

if [ -n "$ZIG_SYSTEM_DIR" ]; then
    [ -d "$ZIG_SYSTEM_DIR" ] || die "no such directory: $ZIG_SYSTEM_DIR"
    export GHOSTTY_ZIG_SYSTEM_DIR="$ZIG_SYSTEM_DIR"
    note "resolving Zig packages from $ZIG_SYSTEM_DIR"
fi

# Zig 0.16 cannot verify a P-521 CA and ignores SSL_CERT_{FILE,DIR}, so behind a
# TLS-intercepting proxy it fetches nothing. Detecting that from here means
# matching error strings a Zig release is free to rename, so the escape hatch is
# named instead of inferred.
build_failed() {
    printf '\n' >&2
    warn "the release build failed."
    warn "if Zig reported a TLS or certificate error, it could not fetch its own"
    warn "packages: Zig $ZIG_VERSION cannot verify a P-521 CA and ignores"
    warn "SSL_CERT_FILE and SSL_CERT_DIR, so a TLS-intercepting proxy blocks every"
    warn "fetch. On a host that can reach deps.files.ghostty.org, fill a package"
    warn "directory — \`=all\` because \`--system\` refuses to fetch even a lazy"
    warn "dependency, so the store has to be complete:"
    printf '\n        cd /path/to/ghostty && zig build --fetch=all\n' >&2
    printf '        # writes ./zig-pkg\n\n' >&2
    warn "copy that directory to this host and build against it:"
    printf '\n        %s --zig-system-dir DIR\n\n' "$0" >&2
    exit 1
}

note "building brd (the first Zig build takes a few minutes)"
cargo build --release --locked --manifest-path "$REPO_ROOT/Cargo.toml" || build_failed

mkdir -p "$PREFIX"
install -m 0755 "$REPO_ROOT/target/release/brd" "$PREFIX/brd"
note "installed $PREFIX/brd"

# The daemon holds live PTYs, so it is never killed here. The socket name is
# stable across versions, so this build talks to the daemon already holding the
# user's shells and the two settle their protocol version in the handshake.
report_path_conflicts "$PREFIX/brd"

case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *)
        # A login shell that resolves no `brd` at all falls back to
        # $HOME/.local/bin - see SERVER_COMMAND in
        # crates/client/src/transport.rs - so only another prefix is out of
        # reach of a client.
        [ "$PREFIX" = "$HOME/.local/bin" ] \
            || warn "$PREFIX is not on PATH; brd will not be found by an SSH login"
        ;;
esac

# systemd kills a user's whole slice at last logout unless lingering is on. The
# daemon leaves sshd's process group, so it survives the connection that
# started it - but not that, and a session it is still running is then reachable
# only by pid.
report_linger() {
    local user
    command -v loginctl >/dev/null 2>&1 || return 0
    user="$(id -un)"
    [ "$(loginctl show-user "$user" --property=Linger --value 2>/dev/null)" = "yes" ] && return 0

    printf '\n'
    warn "systemd will end your user slice at last logout, taking every detached brd session with it."
    warn "to keep sessions across logouts:"
    printf '        sudo loginctl enable-linger %s\n' "$user" >&2
}

report_linger
