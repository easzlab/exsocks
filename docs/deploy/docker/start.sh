#!/bin/bash

set -euo pipefail

EXSOCKS_REP="easzlab/exsocks"
EXSOCKS_VER="v0.8.1"

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
  # check existed container
  docker ps -a --format="{{ .Names }}"|grep exsocks > /dev/null && \
  { logger info "exsocks container already existed!"; exit 0; }

  # down image
  logger info "download: $EXSOCKS_REP:$EXSOCKS_VER"
  docker pull "$EXSOCKS_REP:$EXSOCKS_VER"

  # create
  logger info "start container: exsocks"
  docker run -d \
           --cap-add=NET_ADMIN \
           --env TZ=Asia/Shanghai \
           --name exsocks \
           --network host \
           --restart always \
           --volume "$BASE/config":/app/config \
           --volume "$BASE/logs":/app/logs \
       "$EXSOCKS_REP:$EXSOCKS_VER"
}


function main() {
  BASE=$(cd "$(dirname "$0")"; pwd)
  cd "$BASE"
  mkdir -p "$BASE/logs"
  install_exsocks
}

main "$@"