#!/usr/bin/env bash
# SecureMCP launcher
# Usage: ./start.sh [start|infra|build|stdio|stop|status|logs]
set -Eeuo pipefail

APP_NAME="SecureMCP"
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$ROOT_DIR/.securemcp.pid"
LOG_FILE="$ROOT_DIR/securemcp.log"
PROFILE="${SECUREMCP_PROFILE:-http}"

log()  { printf '\033[1;34m[%s]\033[0m %s\n' "$APP_NAME" "$*"; }
ok()   { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }

check_project() {
  [[ -f "$ROOT_DIR/pom.xml" ]] || die "pom.xml not found. Put start.sh in the SecureMCP project root (next to pom.xml)."
  [[ -f "$ROOT_DIR/docker-compose.yml" || -f "$ROOT_DIR/compose.yml" ]] || die "docker-compose.yml/compose.yml not found in $ROOT_DIR"
}

load_env() {
  if [[ -f "$ROOT_DIR/.env" ]]; then
    # .env is treated as a trusted shell environment file. Do not use untrusted .env files.
    set -a
    # shellcheck disable=SC1091
    source "$ROOT_DIR/.env"
    set +a
  elif [[ -f "$ROOT_DIR/.env.example" ]]; then
    warn ".env is missing. Copy .env.example to .env and set secure passwords/secrets before production use."
  fi
}

check_java_maven() {
  require_cmd java
  require_cmd mvn
  local java_version
  java_version="$(java -version 2>&1 | awk -F '[\".]' '/version/ {print $2; exit}')"
  [[ "$java_version" == "21" ]] || warn "Java 21 is recommended; detected Java version: ${java_version:-unknown}."
  ok "Java and Maven are available."
}

compose() {
  require_cmd docker
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (docker compose)."
  docker compose "$@"
}

start_infrastructure() {
  check_project
  require_cmd docker
  docker info >/dev/null 2>&1 || die "Docker is not running. Start Docker Desktop/Engine and retry."
  log "Starting PostgreSQL and Redis..."
  compose up -d postgres redis
  ok "Infrastructure containers started."
}

build_app() {
  check_project
  check_java_maven
  log "Building and running Maven verification..."
  (cd "$ROOT_DIR" && mvn clean verify)
  ok "Maven build and tests completed."
}

start_http() {
  check_project
  check_java_maven
  load_env
  start_infrastructure

  if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    die "SecureMCP is already running (PID $(cat "$PID_FILE")). Use './start.sh status' or './start.sh stop'."
  fi

  log "Starting SecureMCP with Spring profile '$PROFILE'..."
  cd "$ROOT_DIR"
  nohup mvn spring-boot:run "-Dspring-boot.run.profiles=$PROFILE" \
    >"$LOG_FILE" 2>&1 &
  local app_pid=$!
  printf '%s\n' "$app_pid" > "$PID_FILE"
  sleep 3
  if ! kill -0 "$app_pid" 2>/dev/null; then
    rm -f "$PID_FILE"
    tail -n 80 "$LOG_FILE" >&2 || true
    die "SecureMCP failed to start. See $LOG_FILE"
  fi
  ok "SecureMCP launcher started (PID $app_pid)."
  log "Logs: $LOG_FILE"
  log "HTTP MCP endpoint (when enabled): http://localhost:${SERVER_PORT:-8080}/mcp"
  log "Use './start.sh logs' to follow logs and './start.sh stop' to stop the application."
}

start_stdio() {
  check_project
  check_java_maven
  load_env
  start_infrastructure
  log "Starting STDIO MCP profile in the foreground. Press Ctrl+C to stop."
  cd "$ROOT_DIR"
  exec mvn spring-boot:run -Dspring-boot.run.profiles=stdio
}

stop_app() {
  if [[ ! -f "$PID_FILE" ]]; then
    warn "No PID file found; SecureMCP may not be running."
    return 0
  fi
  local pid
  pid="$(cat "$PID_FILE")"
  if kill -0 "$pid" 2>/dev/null; then
    log "Stopping SecureMCP launcher process $pid..."
    kill "$pid" || true
    for _ in {1..15}; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
      warn "Process did not stop gracefully; sending SIGKILL."
      kill -9 "$pid" 2>/dev/null || true
    fi
    ok "Stop signal sent."
  else
    warn "Process $pid is not running."
  fi
  rm -f "$PID_FILE"
}

show_status() {
  if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    ok "SecureMCP launcher is running (PID $(cat "$PID_FILE"))."
  else
    warn "SecureMCP launcher is not running."
  fi
  if command -v docker >/dev/null 2>&1; then
    docker compose ps 2>/dev/null || true
  fi
}

show_logs() {
  [[ -f "$LOG_FILE" ]] || die "Log file not found: $LOG_FILE. Start SecureMCP first."
  require_cmd tail
  tail -n 100 -f "$LOG_FILE"
}

usage() {
  cat <<USAGE
SecureMCP launcher

Usage: ./start.sh [command]
  start    Start PostgreSQL, Redis and the HTTP-profile application (default)
  infra    Start PostgreSQL and Redis only
  build    Run mvn clean verify
  stdio    Start the STDIO MCP profile in the foreground
  status   Show application and Docker Compose status
  logs     Follow application logs
  stop     Stop the HTTP-profile application
  help     Show this help

Run this script from the SecureMCP project root or keep it in that directory.
USAGE
}

command="${1:-start}"
case "$command" in
  start)  start_http ;;
  infra)  check_project; load_env; start_infrastructure ;;
  build)  build_app ;;
  stdio)  start_stdio ;;
  status) show_status ;;
  logs)   show_logs ;;
  stop)   stop_app ;;
  help|-h|--help) usage ;;
  *) die "Unknown command: $command. Run './start.sh help'." ;;
esac
