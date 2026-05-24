#!/bin/sh

set -u

NZ_BASE_PATH="${NZ_BASE_PATH:-/opt/nezha}"
NZ_DASHBOARD_PATH="${NZ_BASE_PATH}/dashboard"
NZ_AGENT_PATH="${NZ_BASE_PATH}/agent"
NZ_DASHBOARD_SERVICE="/etc/systemd/system/nezha-dashboard.service"
NZ_SOURCE_REPO="${NZ_SOURCE_REPO:-https://github.com/nezha-rs/nezha-rs.git}"
NZ_SOURCE_REF="${NZ_SOURCE_REF:-main}"
NZ_BUILD_DIR="${NZ_BUILD_DIR:-/tmp/nezha-rs-src}"
NZ_MIN_RUST="${NZ_MIN_RUST:-1.95.0}"

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

err() {
    printf "${red}%s${plain}\n" "$*" >&2
}

warn() {
    printf "${yellow}%s${plain}\n" "$*"
}

success() {
    printf "${green}%s${plain}\n" "$*"
}

info() {
    printf "${yellow}%s${plain}\n" "$*"
}

println() {
    printf "%s\n" "$*"
}

as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        err "sudo is not installed. Run this script as root or install sudo."
        exit 1
    fi
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "$1 not found."
        exit 1
    fi
}

check_debian12() {
    if [ "${NZ_SKIP_DEBIAN_CHECK:-0}" = "1" ]; then
        return
    fi
    if [ ! -r /etc/os-release ]; then
        err "Cannot detect OS. This installer targets Debian 12."
        exit 1
    fi
    # shellcheck disable=SC1091
    . /etc/os-release
    if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "12" ]; then
        err "This installer targets Debian 12. Set NZ_SKIP_DEBIAN_CHECK=1 to bypass."
        exit 1
    fi
}

check_systemd() {
    if ! command -v systemctl >/dev/null 2>&1; then
        err "systemd is required."
        exit 1
    fi
}

install_deps() {
    info "> Install build dependencies"
    as_root apt-get update
    as_root apt-get install -y ca-certificates curl git build-essential pkg-config
}

rust_version_ok() {
    command -v rustc >/dev/null 2>&1 || return 1
    current="$(rustc --version | awk '{print $2}' | sed 's/-.*//')"
    min="$NZ_MIN_RUST"
    current_major="$(printf "%s" "$current" | awk -F. '{print $1}')"
    current_minor="$(printf "%s" "$current" | awk -F. '{print $2}')"
    current_patch="$(printf "%s" "$current" | awk -F. '{print $3}')"
    min_major="$(printf "%s" "$min" | awk -F. '{print $1}')"
    min_minor="$(printf "%s" "$min" | awk -F. '{print $2}')"
    min_patch="$(printf "%s" "$min" | awk -F. '{print $3}')"
    current_patch="${current_patch:-0}"
    min_patch="${min_patch:-0}"

    [ "$current_major" -gt "$min_major" ] && return 0
    [ "$current_major" -lt "$min_major" ] && return 1
    [ "$current_minor" -gt "$min_minor" ] && return 0
    [ "$current_minor" -lt "$min_minor" ] && return 1
    [ "$current_patch" -ge "$min_patch" ]
}

load_cargo_env() {
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi
}

install_rust() {
    load_cargo_env
    if rust_version_ok && command -v cargo >/dev/null 2>&1; then
        return
    fi

    info "> Install Rust toolchain with rustup"
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
    load_cargo_env
    require_cmd cargo
    if ! rust_version_ok; then
        err "Rust $NZ_MIN_RUST or newer is required."
        exit 1
    fi
}

script_dir() {
    CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd
}

resolve_source_dir() {
    if [ -n "${NZ_SOURCE_DIR:-}" ]; then
        printf "%s" "$NZ_SOURCE_DIR"
        return
    fi

    dir="$(script_dir)"
    if [ -f "$dir/../Cargo.toml" ]; then
        CDPATH= cd -- "$dir/.." && pwd
        return
    fi

    if [ -d "$NZ_BUILD_DIR/.git" ]; then
        git -C "$NZ_BUILD_DIR" fetch --tags --prune
        git -C "$NZ_BUILD_DIR" checkout "$NZ_SOURCE_REF"
        git -C "$NZ_BUILD_DIR" pull --ff-only || true
    else
        rm -rf "$NZ_BUILD_DIR"
        git clone --depth 1 --branch "$NZ_SOURCE_REF" "$NZ_SOURCE_REPO" "$NZ_BUILD_DIR"
    fi
    printf "%s" "$NZ_BUILD_DIR"
}

build_project() {
    source_dir="$(resolve_source_dir)"
    info "> Build Nezha Rust project from $source_dir"
    (cd "$source_dir" && cargo build --workspace --release)
    NZ_BUILT_DASHBOARD="$source_dir/target/release/nezha-dashboard"
    NZ_BUILT_AGENT="$source_dir/target/release/nezha-agent"
    [ -x "$NZ_BUILT_DASHBOARD" ] || {
        err "nezha-dashboard binary was not built."
        exit 1
    }
    [ -x "$NZ_BUILT_AGENT" ] || {
        err "nezha-agent binary was not built."
        exit 1
    }
}

random_secret() {
    LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-32}"
}

yaml_quote() {
    printf "%s" "$1" | sed "s/'/''/g; s/^/'/; s/$/'/"
}

get_yaml_value() {
    file="$1"
    key="$2"
    if [ -r "$file" ]; then
        awk -F: -v key="$key" '
        $1 == key {
            sub(/^[ \t]*/, "", $2)
            sub(/[ \t]*$/, "", $2)
            gsub(/^"/, "", $2)
            gsub(/"$/, "", $2)
            gsub(/^'\''/, "", $2)
            gsub(/'\''$/, "", $2)
            print $2
            exit
        }
        ' "$file"
    elif command -v sudo >/dev/null 2>&1; then
        sudo awk -F: -v key="$key" '
        $1 == key {
            sub(/^[ \t]*/, "", $2)
            sub(/[ \t]*$/, "", $2)
            gsub(/^"/, "", $2)
            gsub(/"$/, "", $2)
            gsub(/^'\''/, "", $2)
            gsub(/'\''$/, "", $2)
            print $2
            exit
        }
        ' "$file" 2>/dev/null
    else
        return 1
    fi
}

get_env_value() {
    file="$1"
    key="$2"
    if [ -r "$file" ]; then
        awk -F= -v key="$key" '$1 == key {print $2; exit}' "$file"
    elif command -v sudo >/dev/null 2>&1; then
        sudo awk -F= -v key="$key" '$1 == key {print $2; exit}' "$file" 2>/dev/null
    else
        return 1
    fi
}

ask() {
    var="$1"
    prompt="$2"
    default="$3"
    eval "current=\${$var:-}"
    if [ -n "$current" ]; then
        eval "$var=\$current"
        return
    fi
    if [ -t 0 ]; then
        if [ -n "$default" ]; then
            printf "%s [%s]: " "$prompt" "$default"
        else
            printf "%s: " "$prompt"
        fi
        read -r answer
        [ -n "$answer" ] || answer="$default"
    else
        answer="$default"
    fi
    eval "$var=\$answer"
}

ask_bool() {
    var="$1"
    prompt="$2"
    default="$3"
    eval "current=\${$var:-}"
    if [ -n "$current" ]; then
        case "$current" in
            1|true|TRUE|yes|YES|y|Y) eval "$var=true" ;;
            *) eval "$var=false" ;;
        esac
        return
    fi
    if [ -t 0 ]; then
        if [ "$default" = "true" ]; then
            printf "%s [Y/n]: " "$prompt"
        else
            printf "%s [y/N]: " "$prompt"
        fi
        read -r answer
    else
        answer=""
    fi
    [ -n "$answer" ] || answer="$default"
    case "$answer" in
        1|true|TRUE|yes|YES|y|Y) eval "$var=true" ;;
        *) eval "$var=false" ;;
    esac
}

dashboard_config_defaults() {
    config="$NZ_DASHBOARD_PATH/data/config.yaml"
    NZ_SITE_TITLE="${NZ_SITE_TITLE:-$(get_yaml_value "$config" site_name || true)}"
    NZ_HTTP_PORT="${NZ_HTTP_PORT:-$(get_yaml_value "$config" listen_port || true)}"
    NZ_INSTALL_HOST="${NZ_INSTALL_HOST:-$(get_yaml_value "$config" install_host || true)}"
    NZ_AGENT_TLS="${NZ_AGENT_TLS:-$(get_yaml_value "$config" tls || true)}"
    NZ_LANGUAGE="${NZ_LANGUAGE:-$(get_yaml_value "$config" language || true)}"
    NZ_AGENT_SECRET_KEY="${NZ_AGENT_SECRET_KEY:-$(get_yaml_value "$config" agent_secret_key || true)}"
    NZ_JWT_SECRET_KEY="${NZ_JWT_SECRET_KEY:-$(get_yaml_value "$config" jwt_secret_key || true)}"
}

write_dashboard_config() {
    dashboard_config_defaults
    ask NZ_SITE_TITLE "Site title" "Nezha"
    ask NZ_HTTP_PORT "Dashboard HTTP port" "8008"
    ask NZ_INSTALL_HOST "Public install host, e.g. https://nezha.example.com or example.com:443" ""
    ask_bool NZ_AGENT_TLS "Should agents connect to dashboard with TLS" "${NZ_AGENT_TLS:-false}"
    ask NZ_LANGUAGE "Backend language (zh_CN, zh_TW, en_US)" "en_US"
    NZ_AGENT_SECRET_KEY="${NZ_AGENT_SECRET_KEY:-$(random_secret 32)}"
    NZ_JWT_SECRET_KEY="${NZ_JWT_SECRET_KEY:-$(random_secret 96)}"

    tmp="$(mktemp)"
    {
        printf "debug: false\n"
        printf "language: %s\n" "$(yaml_quote "$NZ_LANGUAGE")"
        printf "listen_host: 0.0.0.0\n"
        printf "listen_port: %s\n" "$NZ_HTTP_PORT"
        printf "site_name: %s\n" "$(yaml_quote "$NZ_SITE_TITLE")"
        printf "install_host: %s\n" "$(yaml_quote "$NZ_INSTALL_HOST")"
        printf "tls: %s\n" "$NZ_AGENT_TLS"
        printf "agent_secret_key: %s\n" "$(yaml_quote "$NZ_AGENT_SECRET_KEY")"
        printf "jwt_secret_key: %s\n" "$(yaml_quote "$NZ_JWT_SECRET_KEY")"
        printf "jwt_timeout: 24\n"
        printf "force_auth: false\n"
    } >"$tmp"
    as_root mkdir -p "$NZ_DASHBOARD_PATH/data"
    as_root install -m 0600 "$tmp" "$NZ_DASHBOARD_PATH/data/config.yaml"
    rm -f "$tmp"
}

write_dashboard_env() {
    NZ_ADMIN_USERNAME="${NZ_ADMIN_USERNAME:-admin}"
    if [ -z "${NZ_ADMIN_PASSWORD:-}" ]; then
        NZ_ADMIN_PASSWORD="$(get_env_value "$NZ_DASHBOARD_PATH/.env" NZ_ADMIN_PASSWORD || true)"
    fi
    NZ_ADMIN_PASSWORD="${NZ_ADMIN_PASSWORD:-$(random_secret 18)}"
    tmp="$(mktemp)"
    {
        printf "RUST_LOG=%s\n" "${RUST_LOG:-info}"
        printf "NZ_ADMIN_USERNAME=%s\n" "$NZ_ADMIN_USERNAME"
        printf "NZ_ADMIN_PASSWORD=%s\n" "$NZ_ADMIN_PASSWORD"
    } >"$tmp"
    as_root install -m 0600 "$tmp" "$NZ_DASHBOARD_PATH/.env"
    rm -f "$tmp"
}

write_dashboard_unit() {
    grpc_bind="${NZ_GRPC_BIND:-0.0.0.0:5555}"
    tmp="$(mktemp)"
    cat >"$tmp" <<EOF
[Unit]
Description=Nezha Dashboard (Rust)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$NZ_DASHBOARD_PATH
EnvironmentFile=-$NZ_DASHBOARD_PATH/.env
ExecStart=$NZ_DASHBOARD_PATH/app --config $NZ_DASHBOARD_PATH/data/config.yaml --data $NZ_DASHBOARD_PATH/data/sqlite.db --geoip-db $NZ_DASHBOARD_PATH/data/geoip.db --bind $grpc_bind
Restart=always
RestartSec=5
LimitNOFILE=65535
ProtectSystem=full
ReadWritePaths=$NZ_DASHBOARD_PATH
PrivateTmp=yes
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    as_root install -m 0644 "$tmp" "$NZ_DASHBOARD_SERVICE"
    rm -f "$tmp"
}

reset_dashboard_admin_password() {
    info "> Sync dashboard admin password"
    as_root env "NZ_ADMIN_USERNAME=$NZ_ADMIN_USERNAME" "NZ_ADMIN_PASSWORD=$NZ_ADMIN_PASSWORD" \
        "$NZ_DASHBOARD_PATH/app" --data "$NZ_DASHBOARD_PATH/data/sqlite.db" reset-admin-password || {
        err "failed to sync dashboard admin password"
        exit 1
    }
}

install_binaries() {
    as_root mkdir -p "$NZ_DASHBOARD_PATH" "$NZ_AGENT_PATH"
    as_root install -m 0755 "$NZ_BUILT_DASHBOARD" "$NZ_DASHBOARD_PATH/app"
    as_root install -m 0755 "$NZ_BUILT_AGENT" "$NZ_AGENT_PATH/nezha-agent"
}

restart_dashboard() {
    as_root systemctl daemon-reload
    as_root systemctl enable nezha-dashboard.service
    as_root systemctl restart nezha-dashboard.service
}

install_dashboard() {
    echo "> Install Dashboard"
    prepare_build_env
    build_project
    install_binaries
    write_dashboard_config
    write_dashboard_env
    reset_dashboard_admin_password
    write_dashboard_unit
    restart_dashboard
    success "Dashboard installed."
    info "HTTP:  http://SERVER_IP:${NZ_HTTP_PORT:-8008}/"
    info "Admin: http://SERVER_IP:${NZ_HTTP_PORT:-8008}/dashboard/"
    info "Admin username: ${NZ_ADMIN_USERNAME:-admin}"
    info "Admin password: ${NZ_ADMIN_PASSWORD}"
}

modify_dashboard_config() {
    echo "> Modify Dashboard Configuration"
    init_common
    write_dashboard_config
    write_dashboard_env
    write_dashboard_unit
    restart_dashboard
    success "Dashboard configuration updated."
}

restart_and_update_dashboard() {
    echo "> Restart and Update Dashboard"
    prepare_build_env
    build_project
    install_binaries
    write_dashboard_unit
    restart_dashboard
    success "Dashboard restarted and updated."
}

show_dashboard_log() {
    echo "> Dashboard Log"
    as_root journalctl -xf -u nezha-dashboard.service
}

uninstall_dashboard() {
    echo "> Uninstall Dashboard"
    warn "This removes $NZ_DASHBOARD_PATH and $NZ_DASHBOARD_SERVICE."
    if [ -t 0 ]; then
        printf "Proceed? [y/N]: "
        read -r answer
        case "$answer" in
            y|Y|yes|YES) ;;
            *) return ;;
        esac
    fi
    as_root systemctl stop nezha-dashboard.service >/dev/null 2>&1 || true
    as_root systemctl disable nezha-dashboard.service >/dev/null 2>&1 || true
    as_root rm -f "$NZ_DASHBOARD_SERVICE"
    as_root rm -rf "$NZ_DASHBOARD_PATH"
    as_root systemctl daemon-reload
    success "Dashboard uninstalled."
}

agent_config_defaults() {
    config="$NZ_AGENT_PATH/config.yml"
    NZ_SERVER="${NZ_SERVER:-$(get_yaml_value "$config" server || true)}"
    NZ_CLIENT_SECRET="${NZ_CLIENT_SECRET:-$(get_yaml_value "$config" client_secret || true)}"
    NZ_TLS="${NZ_TLS:-$(get_yaml_value "$config" tls || true)}"
    if [ -z "${NZ_CLIENT_SECRET:-}" ]; then
        NZ_CLIENT_SECRET="$(get_yaml_value "$NZ_DASHBOARD_PATH/data/config.yaml" agent_secret_key || true)"
    fi
}

write_agent_config() {
    agent_config_defaults
    ask NZ_SERVER "Dashboard gRPC server, e.g. example.com:5555" "127.0.0.1:5555"
    ask NZ_CLIENT_SECRET "Agent client secret" ""
    ask_bool NZ_TLS "Connect with TLS" "${NZ_TLS:-false}"
    if [ -z "$NZ_CLIENT_SECRET" ]; then
        err "Agent client secret cannot be empty."
        exit 1
    fi
    tmp="$(mktemp)"
    {
        printf "server: %s\n" "$(yaml_quote "$NZ_SERVER")"
        printf "client_secret: %s\n" "$(yaml_quote "$NZ_CLIENT_SECRET")"
        printf "tls: %s\n" "$NZ_TLS"
        printf "report_delay: 3\n"
        printf "ip_report_period: 1800\n"
        printf "disable_auto_update: false\n"
        printf "disable_force_update: false\n"
        printf "disable_command_execute: false\n"
        printf "disable_nat: false\n"
        printf "disable_send_query: false\n"
    } >"$tmp"
    as_root mkdir -p "$NZ_AGENT_PATH"
    as_root install -m 0600 "$tmp" "$NZ_AGENT_PATH/config.yml"
    rm -f "$tmp"
}

install_agent() {
    echo "> Install Agent"
    prepare_build_env
    build_project
    install_binaries
    write_agent_config
    as_root "$NZ_AGENT_PATH/nezha-agent" --config "$NZ_AGENT_PATH/config.yml" service uninstall >/dev/null 2>&1 || true
    as_root "$NZ_AGENT_PATH/nezha-agent" --config "$NZ_AGENT_PATH/config.yml" service install
    as_root "$NZ_AGENT_PATH/nezha-agent" --config "$NZ_AGENT_PATH/config.yml" service start || \
        as_root "$NZ_AGENT_PATH/nezha-agent" --config "$NZ_AGENT_PATH/config.yml" service restart
    success "Agent installed."
}

modify_agent_config() {
    echo "> Modify Agent Configuration"
    init_common
    if [ ! -x "$NZ_AGENT_PATH/nezha-agent" ]; then
        install_deps
        install_rust
        build_project
        install_binaries
    fi
    write_agent_config
    as_root "$NZ_AGENT_PATH/nezha-agent" --config "$NZ_AGENT_PATH/config.yml" service restart
    success "Agent configuration updated."
}

restart_agent() {
    echo "> Restart Agent"
    as_root "$NZ_AGENT_PATH/nezha-agent" --config "$NZ_AGENT_PATH/config.yml" service restart
}

show_agent_log() {
    echo "> Agent Log"
    service_name="nezha-agent"
    as_root journalctl -xf -u "$service_name.service"
}

uninstall_agent() {
    echo "> Uninstall Agent"
    as_root "$NZ_AGENT_PATH/nezha-agent" --config "$NZ_AGENT_PATH/config.yml" service uninstall >/dev/null 2>&1 || true
    as_root rm -rf "$NZ_AGENT_PATH"
    success "Agent uninstalled."
}

init_common() {
    check_debian12
    check_systemd
}

prepare_build_env() {
    init_common
    install_deps
    install_rust
}

before_show_menu() {
    echo
    info "Press Enter to return to the main menu"
    read -r _
    show_menu
}

show_usage() {
    cat <<EOF
Nezha Rust Debian 12 installer

Usage:
  $0                         Show menu
  $0 install                 Install Dashboard
  $0 modify_config           Modify Dashboard configuration
  $0 restart_and_update      Rebuild, install, and restart Dashboard
  $0 show_log                View Dashboard log
  $0 uninstall               Uninstall Dashboard
  $0 install_agent           Install Agent
  $0 modify_agent_config     Modify Agent configuration
  $0 restart_agent           Restart Agent
  $0 show_agent_log          View Agent log
  $0 uninstall_agent         Uninstall Agent

Environment overrides:
  NZ_SOURCE_DIR=/path/to/nezha-rs
  NZ_SOURCE_REPO=https://github.com/nezha-rs/nezha-rs.git
  NZ_SOURCE_REF=main
  NZ_SITE_TITLE=Nezha
  NZ_HTTP_PORT=8008
  NZ_GRPC_BIND=0.0.0.0:5555
  NZ_INSTALL_HOST=https://nezha.example.com
  NZ_AGENT_TLS=false
  NZ_AGENT_SECRET_KEY=secret
  NZ_ADMIN_USERNAME=admin
  NZ_ADMIN_PASSWORD=password
  NZ_SERVER=example.com:5555
  NZ_CLIENT_SECRET=secret
  NZ_TLS=false
EOF
}

show_menu() {
    println "${green}Nezha Rust Debian 12 Management Script${plain}"
    echo "--- $NZ_SOURCE_REPO ---"
    println "${green}1.${plain}  Install Dashboard"
    println "${green}2.${plain}  Modify Dashboard Configuration"
    println "${green}3.${plain}  Restart and Update Dashboard"
    println "${green}4.${plain}  View Dashboard Log"
    println "${green}5.${plain}  Uninstall Dashboard"
    echo "--------------------------------------------------------"
    println "${green}6.${plain}  Install Agent"
    println "${green}7.${plain}  Modify Agent Configuration"
    println "${green}8.${plain}  Restart Agent"
    println "${green}9.${plain}  View Agent Log"
    println "${green}10.${plain} Uninstall Agent"
    echo "--------------------------------------------------------"
    println "${green}0.${plain}  Exit"
    echo
    printf "Please enter [0-10]: "
    read -r num
    case "$num" in
        0) exit 0 ;;
        1) install_dashboard; before_show_menu ;;
        2) modify_dashboard_config; before_show_menu ;;
        3) restart_and_update_dashboard; before_show_menu ;;
        4) show_dashboard_log ;;
        5) uninstall_dashboard; before_show_menu ;;
        6) install_agent; before_show_menu ;;
        7) modify_agent_config; before_show_menu ;;
        8) restart_agent; before_show_menu ;;
        9) show_agent_log ;;
        10) uninstall_agent; before_show_menu ;;
        *) err "Please enter a number from 0 to 10."; before_show_menu ;;
    esac
}

case "${1:-}" in
    "") show_menu ;;
    install) install_dashboard ;;
    modify_config) modify_dashboard_config ;;
    restart_and_update) restart_and_update_dashboard ;;
    show_log) show_dashboard_log ;;
    uninstall) uninstall_dashboard ;;
    install_agent) install_agent ;;
    modify_agent_config) modify_agent_config ;;
    restart_agent) restart_agent ;;
    show_agent_log) show_agent_log ;;
    uninstall_agent) uninstall_agent ;;
    -h|--help|help) show_usage ;;
    *) show_usage; exit 1 ;;
esac
