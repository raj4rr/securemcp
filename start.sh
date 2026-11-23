#!/usr/bin/env bash
# SecureMCP launcher
# Usage: ./start.sh [start|infra|build|stdio|client-java|client-py|all|stop|status|logs]
set -Eeuo pipefail

APP_NAME="SecureMCP"
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$ROOT_DIR/.securemcp.pid"
LOG_FILE="$ROOT_DIR/securemcp.log"
JAVA_CLIENT_PID_FILE="$ROOT_DIR/.securemcp-client.pid"
JAVA_CLIENT_LOG_FILE="$ROOT_DIR/securemcp-client.log"
PY_CLIENT_PID_FILE="$ROOT_DIR/.client-py.pid"
PY_CLIENT_LOG_FILE="$ROOT_DIR/client-py.log"
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
  [[ "$java_version" == "21" || "$java_version" -ge 21 ]] || warn "Java 21+ is recommended; detected Java version: ${java_version:-unknown}."
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
  if [[ -d "$ROOT_DIR/securemcp-client" ]]; then
    log "Building Java client (securemcp-client)..."
    (cd "$ROOT_DIR/securemcp-client" && mvn clean compile)
  fi
  ok "Maven builds completed."
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
    "-Dspring-boot.run.arguments=--REDIS_PASSWORD=${REDIS_PASSWORD:-securemcp} --SECUREMCP_BOOTSTRAP_CLIENT_SECRET=${SECUREMCP_BOOTSTRAP_CLIENT_SECRET:-securemcp}" \
    >"$LOG_FILE" 2>&1 &
  local app_pid=$!
  printf '%s\n' "$app_pid" > "$PID_FILE"
  sleep 4
  if ! kill -0 "$app_pid" 2>/dev/null; then
    rm -f "$PID_FILE"
    tail -n 80 "$LOG_FILE" >&2 || true
    die "SecureMCP failed to start. See $LOG_FILE"
  fi
  ok "SecureMCP server started (PID $app_pid)."
  log "Logs: $LOG_FILE"
  log "HTTP MCP endpoint: http://localhost:${SERVER_PORT:-8080}/mcp"
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

start_client_java() {
  check_project
  check_java_maven
  local client_dir="$ROOT_DIR/securemcp-client"
  [[ -d "$client_dir" ]] || die "securemcp-client directory not found."

  if [[ -f "$JAVA_CLIENT_PID_FILE" ]] && kill -0 "$(cat "$JAVA_CLIENT_PID_FILE")" 2>/dev/null; then
    die "SecureMCP Java client is already running (PID $(cat "$JAVA_CLIENT_PID_FILE"))."
  fi

  log "Starting Spring AI SecureMCP Client on port 8081..."
  cd "$client_dir"
  nohup mvn spring-boot:run "-Dspring-boot.run.arguments=--server.port=8081" >"$JAVA_CLIENT_LOG_FILE" 2>&1 &
  local client_pid=$!
  printf '%s\n' "$client_pid" > "$JAVA_CLIENT_PID_FILE"
  sleep 4
  if ! kill -0 "$client_pid" 2>/dev/null; then
    rm -f "$JAVA_CLIENT_PID_FILE"
    tail -n 60 "$JAVA_CLIENT_LOG_FILE" >&2 || true
    die "SecureMCP Java client failed to start. See $JAVA_CLIENT_LOG_FILE"
  fi
  ok "SecureMCP Java client started (PID $client_pid)."
  log "Web Chatbot UI: http://localhost:8081"
  log "Logs: $JAVA_CLIENT_LOG_FILE"
}

start_client_py() {
  local client_dir="$ROOT_DIR/client"
  [[ -d "$client_dir" ]] || die "client directory not found."
  require_cmd python3

  if [[ -f "$PY_CLIENT_PID_FILE" ]] && kill -0 "$(cat "$PY_CLIENT_PID_FILE")" 2>/dev/null; then
    die "Python client is already running (PID $(cat "$PY_CLIENT_PID_FILE"))."
  fi

  log "Starting Python SecureMCP Chatbot on port 3000..."
  cd "$ROOT_DIR"
  nohup python3 -m uvicorn app:app --app-dir client --host 127.0.0.1 --port 3000 >"$PY_CLIENT_LOG_FILE" 2>&1 &
  local py_pid=$!
  printf '%s\n' "$py_pid" > "$PY_CLIENT_PID_FILE"
  sleep 2
  if ! kill -0 "$py_pid" 2>/dev/null; then
    rm -f "$PY_CLIENT_PID_FILE"
    tail -n 60 "$PY_CLIENT_LOG_FILE" >&2 || true
    die "Python client failed to start. See $PY_CLIENT_LOG_FILE"
  fi
  ok "Python client started (PID $py_pid)."
  log "Web Chatbot UI: http://localhost:3000"
  log "Logs: $PY_CLIENT_LOG_FILE"
}

start_all() {
  start_http
  log "Waiting 5 seconds for SecureMCP server to initialize..."
  sleep 5
  start_client_java
  ok "All services started! Access Server on :8080 and Java Client on :8081"
}

stop_process() {
  local pid_file="$1"
  local name="$2"
  if [[ ! -f "$pid_file" ]]; then
    return 0
  fi
  local pid
  pid="$(cat "$pid_file")"
  if kill -0 "$pid" 2>/dev/null; then
    log "Stopping $name process $pid..."
    kill "$pid" || true
    for _ in {1..15}; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
      warn "$name process did not stop gracefully; sending SIGKILL."
      kill -9 "$pid" 2>/dev/null || true
    fi
    ok "Stopped $name."
  else
    warn "Process $pid ($name) is not running."
  fi
  rm -f "$pid_file"
}

stop_all() {
  stop_process "$JAVA_CLIENT_PID_FILE" "SecureMCP Java Client"
  stop_process "$PY_CLIENT_PID_FILE" "Python Client"
  stop_process "$PID_FILE" "SecureMCP Server"
}

show_status() {
  echo "--- Process Status ---"
  if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    ok "SecureMCP Server is running (PID $(cat "$PID_FILE"))."
  else
    warn "SecureMCP Server is not running."
  fi

  if [[ -f "$JAVA_CLIENT_PID_FILE" ]] && kill -0 "$(cat "$JAVA_CLIENT_PID_FILE")" 2>/dev/null; then
    ok "SecureMCP Java Client is running (PID $(cat "$JAVA_CLIENT_PID_FILE"), Port 8081)."
  else
    warn "SecureMCP Java Client is not running."
  fi

  if [[ -f "$PY_CLIENT_PID_FILE" ]] && kill -0 "$(cat "$PY_CLIENT_PID_FILE")" 2>/dev/null; then
    ok "Python Client is running (PID $(cat "$PY_CLIENT_PID_FILE"), Port 3000)."
  else
    warn "Python Client is not running."
  fi

  if command -v docker >/dev/null 2>&1; then
    echo "--- Docker Containers ---"
    docker compose ps 2>/dev/null || true
  fi
}

show_logs() {
  local target="${1:-server}"
  case "$target" in
    server)
      [[ -f "$LOG_FILE" ]] || die "Log file not found: $LOG_FILE"
      tail -n 100 -f "$LOG_FILE"
      ;;
    client-java)
      [[ -f "$JAVA_CLIENT_LOG_FILE" ]] || die "Log file not found: $JAVA_CLIENT_LOG_FILE"
      tail -n 100 -f "$JAVA_CLIENT_LOG_FILE"
      ;;
    client-py)
      [[ -f "$PY_CLIENT_LOG_FILE" ]] || die "Log file not found: $PY_CLIENT_LOG_FILE"
      tail -n 100 -f "$PY_CLIENT_LOG_FILE"
      ;;
    *) die "Unknown log target: $target (use 'server', 'client-java', or 'client-py')" ;;
  esac
}

usage() {
  cat <<USAGE
SecureMCP launcher

Usage: ./start.sh [command]
  start        Start PostgreSQL, Redis and the SecureMCP Server on :8080 (default)
  client-java  Start the Spring Boot + Spring AI Client Chatbot on :8081
  client-py    Start the Python / FastAPI Client Chatbot on :3000
  all          Start SecureMCP Server and the Spring AI Client Chatbot
  infra        Start PostgreSQL and Redis containers only
  build        Run Maven build and verification across modules
  stdio        Start the STDIO MCP profile in the foreground
  status       Show status of Server, Clients, and Docker containers
  logs [target]Follow logs ('server' [default], 'client-java', or 'client-py')
  stop         Stop all running SecureMCP processes (server & clients)
  help         Show this help
USAGE
}

command="${1:-start}"
case "$command" in
  start)        start_http ;;
  client-java)  start_client_java ;;
  client-py)    start_client_py ;;
  all)          start_all ;;
  infra)        check_project; load_env; start_infrastructure ;;
  build)        build_app ;;
  stdio)        start_stdio ;;
  status)       show_status ;;
  logs)         show_logs "${2:-server}" ;;
  stop)         stop_all ;;
  help|-h|--help) usage ;;
  *) die "Unknown command: $command. Run './start.sh help'." ;;
esac
