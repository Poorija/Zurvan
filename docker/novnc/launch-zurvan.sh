#!/usr/bin/env bash
set -euo pipefail

cd /opt/zurvan

mkdir -p /opt/zurvan/data

if [[ -f /opt/zurvan/zurvan_user_data.db && ! -L /opt/zurvan/zurvan_user_data.db && ! -f /opt/zurvan/data/zurvan_user_data.db ]]; then
  mv /opt/zurvan/zurvan_user_data.db /opt/zurvan/data/zurvan_user_data.db
fi

if [[ ! -e /opt/zurvan/zurvan_user_data.db ]]; then
  ln -s /opt/zurvan/data/zurvan_user_data.db /opt/zurvan/zurvan_user_data.db
fi

if [[ -f /opt/zurvan/cve.db && ! -L /opt/zurvan/cve.db && ! -f /opt/zurvan/data/cve.db ]]; then
  mv /opt/zurvan/cve.db /opt/zurvan/data/cve.db
fi

if [[ ! -e /opt/zurvan/cve.db && -f /opt/zurvan/data/cve.db ]]; then
  ln -s /opt/zurvan/data/cve.db /opt/zurvan/cve.db
fi

if [[ ! -f /opt/zurvan/data/zurvan_user_data.db ]]; then
  echo "[Zurvan/noVNC] Initializing database..."
  python3 - <<'PY'
import database
database.initialize_database()
PY
fi

echo "================================================="
echo "[Zurvan/noVNC] Default login:"
echo "  username: admin"
echo "  password: P@ssw0rd1234567890"
echo "[Zurvan/noVNC] Open: http://localhost:${NOVNC_PORT:-6080}/vnc.html"
echo "================================================="

exec bash -lc "$*"