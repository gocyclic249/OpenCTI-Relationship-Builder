#!/usr/bin/env bash
#
# install-deps.sh -- install the development tooling octi-rb needs, and
# (optionally) refresh its actor-synonym crosswalk cache.
#
# octi-rb itself has NO runtime dependencies: it is Python 3 standard library
# only (urllib, tomllib; no pycti, no requests). The only things that need
# installing are the lint/type toolchain that pyproject.toml pins, plus a
# working pip to get it.
#
#   - python3 >= 3.11   runtime      -- verified, never installed
#   - pip               bootstrap    -- distro package (python3-pip)
#   - ruff              lint         -- pip install --user
#   - mypy              type check   -- pip install --user
#   - pytest            tests        -- pip install --user
#   - shellcheck        shell lint   -- distro package
#
# After the toolchain is present, this script also refreshes the MISP
# threat-actor galaxy crosswalk cache (octi-rb crosswalk refresh) if
# bin/octi-rb is present next to this script. A network failure there is a
# WARNING, never an install failure -- the crosswalk is an enrichment, not a
# hard dependency (see octirb/resolvers/crosswalk.py).
#
# Idempotent: every tool is probed with `command -v` first and skipped if
# found; the crosswalk step is skipped if the cache file already exists.
#
# Privilege policy: this script NEVER escalates silently. System packages are
# installed with an explicit `sudo`, and the exact command line is echoed to
# stderr before it runs. If the script is not root and `sudo` is absent, it
# prints the commands you need to run yourself and exits EX_NOPRIV.
#
# Usage:
#   ./install-deps.sh            install whatever is missing, refresh crosswalk
#   ./install-deps.sh --check    report presence only, install/refresh nothing
#   ./install-deps.sh --help
#
# Exit codes:
#   0  EX_OK        success; with --check, everything needed is present
#   1  EX_USAGE     bad command line
#   2  EX_DISTRO    unsupported distribution (not Debian/Ubuntu/Fedora family)
#   3  EX_PYTHON    python3 missing, or older than 3.11
#   4  EX_NOPRIV    root needed for a system package, and sudo is unavailable
#   5  EX_PKGMGR    apt-get/dnf failed
#   6  EX_PIP       pip bootstrap failed, or a pip install failed
#   7  EX_MISSING   --check only: something needed is missing
#
set -euo pipefail

readonly EX_OK=0
readonly EX_USAGE=1
readonly EX_DISTRO=2
readonly EX_PYTHON=3
readonly EX_NOPRIV=4
readonly EX_PKGMGR=5
readonly EX_PIP=6
readonly EX_MISSING=7

readonly MIN_PY_MAJOR=3
readonly MIN_PY_MINOR=11
readonly USER_BIN="$HOME/.local/bin"
readonly CROSSWALK_CACHE_NAME="threat-actor-galaxy.json"

# Populated by detect_distro().
PKG_MGR=""
DISTRO_ID=""
# Set by --check.
CHECK_ONLY=0

log()  { printf '%s\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }
err()  { printf 'error: %s\n' "$*" >&2; }

# die <exit-code> <message...>
die() {
    local code="$1"
    shift
    err "$*"
    exit "$code"
}

have() { command -v "$1" >/dev/null; }

usage() {
    cat <<'EOF'
install-deps.sh -- install octi-rb's development tooling (ruff, mypy,
pytest, shellcheck) and refresh its actor-synonym crosswalk cache.

octi-rb has no runtime dependencies; it is Python 3 stdlib only and needs
python3 >= 3.11, which this script verifies but never installs.

  -h, --help    show this help and exit
      --check   report what is present/missing, install/refresh nothing.
                Exits 0 if everything needed is present, 7 otherwise.

Exit codes: 0 ok, 1 usage, 2 unsupported distro, 3 python, 4 no privileges,
5 package manager, 6 pip, 7 --check found something missing.
EOF
}

parse_args() {
    local arg
    for arg in "$@"; do
        case "$arg" in
            -h|--help) usage; exit "$EX_OK" ;;
            --check)   CHECK_ONLY=1 ;;
            *)         err "unknown argument: $arg"; usage >&2; exit "$EX_USAGE" ;;
        esac
    done
}

# ---------------------------------------------------------------- environment

detect_distro() {
    local os_release="/etc/os-release"
    [ -r "$os_release" ] || die "$EX_DISTRO" "cannot read $os_release; unsupported system"

    local ID="" ID_LIKE=""
    # shellcheck source=/dev/null
    . "$os_release"
    DISTRO_ID="${ID:-unknown}"

    case " ${ID:-} ${ID_LIKE:-} " in
        *" debian "*|*" ubuntu "*)          PKG_MGR="apt-get" ;;
        *" fedora "*|*" rhel "*|*" centos "*) PKG_MGR="dnf" ;;
        *) die "$EX_DISTRO" \
               "unsupported distribution '${ID:-unknown}' (ID_LIKE='${ID_LIKE:-}'); this script supports Debian, Ubuntu and Fedora" ;;
    esac

    have "$PKG_MGR" || die "$EX_DISTRO" \
        "distribution '$DISTRO_ID' selected package manager '$PKG_MGR', but it is not on PATH"
    log "distro: $DISTRO_ID (package manager: $PKG_MGR)"
}

require_python() {
    have python3 || die "$EX_PYTHON" "python3 not found on PATH; install Python >= ${MIN_PY_MAJOR}.${MIN_PY_MINOR} first"

    local version
    version="$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')" \
        || die "$EX_PYTHON" "python3 is on PATH but failed to run"

    if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (${MIN_PY_MAJOR}, ${MIN_PY_MINOR}) else 1)"; then
        die "$EX_PYTHON" "python3 is $version; octi-rb requires >= ${MIN_PY_MAJOR}.${MIN_PY_MINOR}"
    fi
    log "python3: $version (>= ${MIN_PY_MAJOR}.${MIN_PY_MINOR}, ok)"
}

# ----------------------------------------------------------------- privileges

# run_privileged <command...> -- run as root, announcing exactly what it runs.
run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        log "running as root: $*"
        "$@" || return "$EX_PKGMGR"
        return "$EX_OK"
    fi
    if ! have sudo; then
        err "root privileges are required and sudo is not installed."
        err "run this as root, or run the following yourself:"
        printf '    %s\n' "$*" >&2
        return "$EX_NOPRIV"
    fi
    log "escalating with sudo: sudo $*"
    sudo "$@" || return "$EX_PKGMGR"
    return "$EX_OK"
}

# install_system_package <package-name>
install_system_package() {
    local pkg="$1"
    [ -n "$pkg" ] || die "$EX_USAGE" "install_system_package called with an empty package name"

    local rc=0
    if [ "$PKG_MGR" = "apt-get" ]; then
        run_privileged apt-get update || rc=$?
        [ "$rc" -eq 0 ] || return "$rc"
        run_privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" || rc=$?
    else
        run_privileged dnf install -y "$pkg" || rc=$?
    fi
    return "$rc"
}

# ------------------------------------------------------------------ pip tools

# Debian/Ubuntu/Fedora mark the system interpreter PEP 668 externally-managed,
# which blocks even `--user` installs. We deliberately override it for the user
# site only; nothing here touches system site-packages.
pip_extra_flags() {
    local stdlib
    stdlib="$(python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')"
    if [ -e "$stdlib/EXTERNALLY-MANAGED" ]; then
        printf '%s' "--break-system-packages"
    fi
}

ensure_pip() {
    if python3 -m pip --version >/dev/null; then
        log "skip pip: already usable via 'python3 -m pip'"
        return "$EX_OK"
    fi
    log "pip: 'python3 -m pip' does not work; installing distro package python3-pip"
    local rc=0
    install_system_package "python3-pip" || rc=$?
    [ "$rc" -eq 0 ] || return "$rc"

    python3 -m pip --version >/dev/null \
        || die "$EX_PIP" "installed python3-pip but 'python3 -m pip' still does not work"
    log "pip: bootstrapped"
    return "$EX_OK"
}

# ensure_pip_tool <command> <pip-distribution>
ensure_pip_tool() {
    local cmd="$1" dist="$2"
    [ -n "$cmd" ] && [ -n "$dist" ] || die "$EX_USAGE" "ensure_pip_tool needs a command and a distribution"

    if have "$cmd"; then
        log "skip $cmd: already present at $(command -v "$cmd")"
        return "$EX_OK"
    fi

    local rc=0
    ensure_pip || rc=$?
    [ "$rc" -eq 0 ] || return "$rc"

    local flags
    flags="$(pip_extra_flags)"
    log "installing $dist with: python3 -m pip install --user $flags $dist"
    if [ -n "$flags" ]; then
        python3 -m pip install --user "$flags" "$dist" || return "$EX_PIP"
    else
        python3 -m pip install --user "$dist" || return "$EX_PIP"
    fi

    have "$cmd" || warn "$dist installed, but '$cmd' is not on PATH; add $USER_BIN to PATH"
    return "$EX_OK"
}

# ensure_system_tool <command> <package>
ensure_system_tool() {
    local cmd="$1" pkg="$2"
    [ -n "$cmd" ] && [ -n "$pkg" ] || die "$EX_USAGE" "ensure_system_tool needs a command and a package"

    if have "$cmd"; then
        log "skip $cmd: already present at $(command -v "$cmd")"
        return "$EX_OK"
    fi
    log "installing $cmd from distro package $pkg"
    install_system_package "$pkg"
}

# ------------------------------------------------------------------ crosswalk

# repo_root -- directory this script lives in, so it works from any cwd.
repo_root() {
    cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
}

# crosswalk_cache_path -- octi-rb's default cache location (no [runs].dir /
# $OCTI_RB_CONFIG override; see octirb/config.py Config.cache_dir and
# resolvers/crosswalk.py CACHE_NAME). A custom runs dir moves this, but a
# static install script has no config to read, so it reports the default.
crosswalk_cache_path() {
    local state_base="${XDG_STATE_HOME:-$HOME/.local/state}"
    printf '%s/octi-rb/cache/%s' "$state_base" "$CROSSWALK_CACHE_NAME"
}

report_crosswalk() {
    local cache
    cache="$(crosswalk_cache_path)"
    if [ -f "$cache" ]; then
        printf 'crosswalk\tpresent\t%s\n' "$cache"
        return 0
    fi
    printf 'crosswalk\tmissing\t%s\n' "$cache"
    return 1
}

# refresh_crosswalk <root> -- best-effort; never fails the install.
refresh_crosswalk() {
    local root="$1"
    local octi_rb="$root/bin/octi-rb"
    [ -x "$octi_rb" ] || { log "skip crosswalk: $octi_rb not found or not executable"; return; }

    local cache
    cache="$(crosswalk_cache_path)"
    if [ -f "$cache" ]; then
        log "skip crosswalk refresh: cache already present at $cache"
        return
    fi

    log "refreshing crosswalk cache: $octi_rb crosswalk refresh"
    if ! "$octi_rb" crosswalk refresh >&2; then
        warn "crosswalk refresh failed (likely no network); resolution stays platform-only until you run '$octi_rb crosswalk refresh' yourself"
    fi
}

# ---------------------------------------------------------------------- modes

# report_tool <command> -- one stdout line; returns 1 when missing.
report_tool() {
    local cmd="$1" path
    if path="$(command -v "$cmd")"; then
        printf '%s\tpresent\t%s\n' "$cmd" "$path"
        return 0
    fi
    printf '%s\tmissing\t-\n' "$cmd"
    return 1
}

run_check() {
    local missing=0

    if have python3 && python3 -c "import sys; sys.exit(0 if sys.version_info >= (${MIN_PY_MAJOR}, ${MIN_PY_MINOR}) else 1)"; then
        printf 'python3\tpresent\t%s\n' "$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
    else
        printf 'python3\tmissing\t>=%d.%d required\n' "$MIN_PY_MAJOR" "$MIN_PY_MINOR"
        missing=$((missing + 1))
    fi

    local tool
    for tool in ruff mypy shellcheck pytest; do
        report_tool "$tool" || missing=$((missing + 1))
    done

    # pip is a means, not an end: it is only needed when ruff or mypy is absent,
    # so its absence is reported but never counted as missing.
    if python3 -m pip --version >/dev/null; then
        printf 'pip\tpresent\tpython3 -m pip\n'
    else
        printf 'pip\tmissing\t-\n'
    fi

    # crosswalk cache presence is reported, never counted toward --check's
    # required set: it is an enrichment, not a hard dependency.
    report_crosswalk || true

    if [ "$missing" -gt 0 ]; then
        log "$missing required item(s) missing; run this script without --check to install"
        return "$EX_MISSING"
    fi
    log "all required tooling is present"
    return "$EX_OK"
}

run_install() {
    detect_distro
    require_python

    local rc=0
    ensure_pip_tool ruff ruff || rc=$?
    [ "$rc" -eq 0 ] || return "$rc"
    ensure_pip_tool mypy mypy || rc=$?
    [ "$rc" -eq 0 ] || return "$rc"
    ensure_pip_tool pytest pytest || rc=$?
    [ "$rc" -eq 0 ] || return "$rc"
    # Debian/Ubuntu ship it lowercase; Fedora ships it CamelCase.
    local shellcheck_pkg="shellcheck"
    if [ "$PKG_MGR" = "dnf" ]; then
        shellcheck_pkg="ShellCheck"
    fi
    ensure_system_tool shellcheck "$shellcheck_pkg" || rc=$?
    [ "$rc" -eq 0 ] || return "$rc"

    case ":${PATH}:" in
        *":$USER_BIN:"*) ;;
        *) warn "$USER_BIN is not on PATH; pip --user installs will not be runnable until it is" ;;
    esac

    refresh_crosswalk "$(repo_root)"

    log "done. Verify with: ruff check octirb/ tests/ && mypy --strict octirb/ && shellcheck install-deps.sh && pytest -q"
    return "$EX_OK"
}

main() {
    parse_args "$@"
    if [ "$CHECK_ONLY" -eq 1 ]; then
        run_check
        return $?
    fi
    run_install
}

main "$@"
