#!/bin/sh
# SPDX-FileCopyrightText: 2026 Tobias Mueller <muelli@cryptobitch.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
# Runs every test inside throwaway containers. Usage: tests/run.sh
set -e
cd "$(dirname "$0")/.."
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
PY=docker.io/library/python:3.12-slim
NODE=docker.io/library/node:24-slim

podman run --rm -v "$PWD":/work:ro -v "$out":/out -w /tmp "$PY" sh -c '
  pip install -q uv pytest 2>&1 | tail -1
  uv run -q /work/make_fixture.py /out/fake
  uv run -q /work/signal_takeout.py --data-dir /out/fake -o /out/export
  cd /work && uv run -q --with pytest --with sqlcipher3-binary --with cryptography --with tqdm --with jinja2 \
    pytest -q -p no:cacheprovider tests'

podman run --rm -v "$PWD/tests/js":/work:ro -v "$out":/out -w /tmp "$NODE" sh -c '
  cp -r /work /tmp/js && cd /tmp/js && npm install --silent --no-audit --no-fund >/dev/null 2>&1
  EXPORT_DIR=/out/export node --test'
