#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: doctor-strict.sh <container-image>}"
setup="$(cargo run --quiet -p umbra-server -- opaque setup generate)"
common=(
  --network host
  -e UMBRA__DATABASE__BACKEND=postgres
  -e UMBRA__DATABASE__URL=postgres://umbra:umbra@127.0.0.1:5432/umbra_test
  -e UMBRA__MIGRATIONS__AUTO_MIGRATE=false
  -e UMBRA__MIGRATIONS__REQUIRE_LATEST=true
  -e UMBRA__AUTH__OPAQUE__SERVER_SETUP="$setup"
  -e UMBRA__AUTH__OPAQUE__ALLOW_EPHEMERAL_SETUP=false
  -e UMBRA__SERVER__BIND=0.0.0.0:8080
  -e UMBRA__SERVER__PUBLIC_URL=https://umbra.example.test
)

docker run --rm "${common[@]}" "$image" migrate
output="$(docker run --rm "${common[@]}" "$image" doctor --strict --json)"
test "$(jq -r '.migrations' <<<"$output")" = Clean
test "$(jq -r '.opaque_server_setup' <<<"$output")" = persistent
test "$(jq -r '.warnings | length' <<<"$output")" = 0
