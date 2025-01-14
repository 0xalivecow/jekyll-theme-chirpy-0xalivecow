#!/bin/bash
set -e

git config --global --add safe.directory /app
rm -f /app/tmp/pids/server.pid
gem update --system
bundle install

# Then exec the container's main process (what's set as CMD in the Dockerfile or
# as command in the docker-compose.yml).
exec "$@"
