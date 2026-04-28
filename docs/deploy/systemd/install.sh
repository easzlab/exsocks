#!/bin/bash

set -euo pipefail

WORKDIR="/opt/easzlab"

function logger() {
  TIMESTAMP=$(date +'%Y-%m-%d %H:%M:%S')
  case "$1" in
    debug)
      echo -e "$TIMESTAMP \033[36mDEBUG\033[0m $2"
      ;;
    info)
      echo -e "$TIMESTAMP \033[32mINFO\033[0m $2"
      ;;
    warn)
      echo -e "$TIMESTAMP \033[33mWARN\033[0m $2"
      ;;
    error)
      echo -e "$TIMESTAMP \033[31mERROR\033[0m $2"
      ;;
    *)
      ;;
  esac
}

function install_exsocks() {
  logger debug "install exsocks.service..."
  cat > /etc/systemd/system/exsocks.service << EOF
[Unit]
Description=exsocks - High-Performance SOCKS5 Proxy Server
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/easzlab
ExecStart=/opt/easzlab/exsocks -c config/server.yaml
Restart=always
RestartSec=15
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity

[Install]
WantedBy=multi-user.target
EOF

  logger debug "enable and start exsocks server..."
  systemctl enable exsocks
  systemctl daemon-reload && systemctl restart exsocks && sleep 1
}

function main(){
  BASE=$(cd "$(dirname "$0")" || exit 1; pwd)
  mkdir -p "${WORKDIR}/config"

  # check if already installed
  [[ -f "/etc/systemd/system/exsocks.service" ]] && { logger warn "already installed"; exit 0; }

  [[ -f "$BASE/exsocks" ]] || { logger error "exsocks binary file not found"; exit 1; }
  [[ -f "$BASE/config/server.yaml" ]] || { logger error "exsocks config file not found"; exit 1; }

  [[ -f "$WORKDIR/exsocks" ]] || \
  { logger debug "copy exsocks binary"; cp -f "$BASE/exsocks" "$WORKDIR/exsocks"; }

  [[ -f "$WORKDIR/config/server.yaml" ]] || \
  { logger debug "copy exsocks config"; cp -f "$BASE"/config/*.yaml "$WORKDIR/config/"; }

  install_exsocks

  logger info "install success"
}

main "$@"