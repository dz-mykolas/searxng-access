#!/usr/bin/env bash
set -euo pipefail

image="${1:-searxng-access:ci}"
container_name="${SMOKE_CONTAINER_NAME:-searxng-access-smoke}"
host_port="${SMOKE_HOST_PORT:-18080}"
smoke_token="${SMOKE_TOKEN:-container-smoke-token}"
quota_headers=""

cleanup() {
  result=$?
  trap - EXIT

  if ((result != 0)); then
    echo "Container logs:" >&2
    docker logs "$container_name" >&2 || true
  fi

  docker rm --force "$container_name" >/dev/null 2>&1 || true
  if [[ -n "$quota_headers" ]]; then
    rm -f "$quota_headers"
  fi

  exit "$result"
}
trap cleanup EXIT

assert_status() {
  local label="$1"
  local expected="$2"
  local actual="$3"

  if [[ "$actual" != "$expected" ]]; then
    printf '%s: expected HTTP %s, got %s\n' "$label" "$expected" "$actual" >&2
    return 1
  fi
  printf '%s: HTTP %s\n' "$label" "$actual"
}

docker run --detach \
  --name "$container_name" \
  --publish "127.0.0.1:${host_port}:8080" \
  --env SEARXNG_ACCESS_DEV_TOKEN="$smoke_token" \
  --env SEARXNG_ACCESS_SECURE_COOKIE=false \
  "$image" >/dev/null

health_status="000"
for attempt in {1..60}; do
  health_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    "http://127.0.0.1:${host_port}/healthz" || true)
  if [[ "$health_status" == "200" ]]; then
    break
  fi
  sleep 1
done
assert_status "Health check" "200" "$health_status"

missing_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:${host_port}/config")
api_key_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header "X-API-Key: $smoke_token" \
  "http://127.0.0.1:${host_port}/config")
bearer_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header "Authorization: Bearer $smoke_token" \
  "http://127.0.0.1:${host_port}/config")

assert_status "Missing authentication" "401" "$missing_status"
assert_status "X-API-Key authentication" "200" "$api_key_status"
assert_status "Bearer authentication" "200" "$bearer_status"

limited_token=$(docker exec "$container_name" \
  searxng-access token create \
    --label smoke-test \
    --capability search \
    --limit 1 \
    --window 60 \
  | awk '$1 == "Token:" { print $2 }')
if [[ -z "$limited_token" ]]; then
  echo "Token CLI did not return a token" >&2
  exit 1
fi

first_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header "X-API-Key: $limited_token" \
  "http://127.0.0.1:${host_port}/")
quota_headers=$(mktemp)
second_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --dump-header "$quota_headers" \
  --header "X-API-Key: $limited_token" \
  "http://127.0.0.1:${host_port}/")
if [[ "$second_status" == "200" ]]; then
  second_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --dump-header "$quota_headers" \
    --header "X-API-Key: $limited_token" \
    "http://127.0.0.1:${host_port}/")
fi

assert_status "First limited request" "200" "$first_status"
assert_status "Exhausted quota" "429" "$second_status"

if ! tr -d '\r' < "$quota_headers" \
  | grep --ignore-case --extended-regexp --quiet '^Retry-After: [1-9][0-9]*$'; then
  echo "Quota response did not include a positive Retry-After header:" >&2
  cat "$quota_headers" >&2
  exit 1
fi
echo "Retry-After header: present"
