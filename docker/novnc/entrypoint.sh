#!/usr/bin/env bash
set -euo pipefail

DISPLAY="${DISPLAY:-:1}"
NOVNC_PORT="${NOVNC_PORT:-6080}"
VNC_PORT="${VNC_PORT:-5900}"
# تنظیم رزولوشن پایه به کیفیت بالا
VNC_GEOMETRY="${VNC_GEOMETRY:-1920x1080}"
VNC_DEPTH="${VNC_DEPTH:-24}"
VNC_PASSWORD="${VNC_PASSWORD:-}"
ZURVAN_CMD="${ZURVAN_CMD:-python3 /opt/zurvan/zurvan.py}"
XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp/runtime-zurvan}"

export DISPLAY
export XDG_RUNTIME_DIR
export QT_X11_NO_MITSHM="${QT_X11_NO_MITSHM:-1}"
export QTWEBENGINE_CHROMIUM_FLAGS="${QTWEBENGINE_CHROMIUM_FLAGS:---no-sandbox --disable-dev-shm-usage --disable-gpu}"
# حیاتی برای جلوگیری از سیاه شدن صفحه لودینگ در محیط داکر
export LIBGL_ALWAYS_SOFTWARE=1 

mkdir -p "${XDG_RUNTIME_DIR}" /tmp/.X11-unix
chmod 700 "${XDG_RUNTIME_DIR}"

cleanup() {
  echo "[Zurvan/noVNC] Shutting down services..."
  vncserver -kill "${DISPLAY}" 2>/dev/null || true
  jobs -pr | xargs -r kill 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# پاک کردن فایل‌های Lock قدیمی در صورت ریستارت غیرمنتظره کانتینر
rm -f "/tmp/.X${DISPLAY#:}-lock"
rm -f "/tmp/.X11-unix/X${DISPLAY#:}"

# پیکربندی فایل راه‌انداز دسکتاپ (xstartup) برای TigerVNC
mkdir -p ~/.vnc
cat <<EOF > ~/.vnc/xstartup
#!/bin/sh
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
openbox-session &
EOF
chmod +x ~/.vnc/xstartup

# تنظیمات امنیتی و رمز عبور VNC
if [[ -n "${VNC_PASSWORD}" ]]; then
  echo "[Zurvan/noVNC] Setting VNC password..."
  echo "${VNC_PASSWORD}" | vncpasswd -f > ~/.vnc/passwd
  chmod 600 ~/.vnc/passwd
  SEC_ARGS="-SecurityTypes VncAuth -PasswordFile ~/.vnc/passwd"
else
  echo "[Zurvan/noVNC] No VNC password set. Running insecurely."
  SEC_ARGS="-SecurityTypes None"
fi

# اجرای TigerVNC (جایگزین یکپارچه برای Xvfb و x11vnc)
echo "[Zurvan/noVNC] Starting TigerVNC on ${DISPLAY} (${VNC_GEOMETRY}x${VNC_DEPTH})..."
vncserver "${DISPLAY}" -geometry "${VNC_GEOMETRY}" -depth "${VNC_DEPTH}" -rfbport "${VNC_PORT}" -localhost no ${SEC_ARGS}

# اجرای رابط وب noVNC
echo "[Zurvan/noVNC] Starting noVNC on http://0.0.0.0:${NOVNC_PORT}/vnc.html ..."
websockify \
  --web=/usr/share/novnc \
  "0.0.0.0:${NOVNC_PORT}" \
  "127.0.0.1:${VNC_PORT}" \
  >/tmp/novnc.log 2>&1 &

echo "[Zurvan/noVNC] Launch command: ${ZURVAN_CMD}"
exec /opt/zurvan/docker/novnc/launch-zurvan.sh "${ZURVAN_CMD}"